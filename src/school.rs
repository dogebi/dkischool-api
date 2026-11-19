// 이관한 학교 자료 조회, 이미지 프록시와 일괄 등록을 처리합니다.
use super::{AppState, message};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::collections::HashMap;

pub(super) const PUBLIC_CONTENT: &str = "COALESCE(payload->>'access_status', '') <> 'restricted'";
const MAX_SOURCE_IMAGE_BYTES: usize = 20 * 1024 * 1024;
const ALLOWED_IMAGE_HOSTS: [&str; 16] = [
    "dkischool.org",
    "www.dkischool.org",
    "dkischool.withschool.co.kr",
    "www.withschool.co.kr",
    "withschool.co.kr",
    "dkis.withschool.co.kr",
    "news.einfomax.co.kr",
    "www.womennews.co.kr",
    "cjimage.joins.com",
    "www.inews24.com",
    "www.topik.go.kr",
    "ggg.hs.kr",
    "postfiles4.naver.net",
    "cfile8.uf.tistory.com",
    "i1.daumcdn.net",
    "img.morningreading.org",
];

#[derive(Deserialize)]
struct SiteImport {
    pages: Vec<serde_json::Value>,
    articles: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct SitePageQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

async fn site_page(State(state): State<AppState>, Path(menu_no): Path<String>) -> Response {
    match sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "SELECT payload FROM site_pages WHERE menu_no = $1 AND {PUBLIC_CONTENT}"
    ))
    .bind(menu_no)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => message(StatusCode::NOT_FOUND, "Page not found"),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "Content lookup failed"),
    }
}

pub(super) fn allowed_source_image_url(url: &reqwest::Url) -> bool {
    ["http", "https"].contains(&url.scheme())
        && ALLOWED_IMAGE_HOSTS.contains(&url.host_str().unwrap_or_default())
        && url.username().is_empty()
        && url.password().is_none()
        && (url.port().is_none()
            || (url.scheme() == "https"
                && ((url.host_str() == Some("withschool.co.kr") && url.port() == Some(3187))
                    || (url.host_str() == Some("ggg.hs.kr") && url.port() == Some(535)))))
}

async fn proxy_site_image(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(raw_url) = query.get("url") else {
        return message(StatusCode::BAD_REQUEST, "Image URL is required");
    };
    let Ok(url) = reqwest::Url::parse(raw_url) else {
        return message(StatusCode::BAD_REQUEST, "Invalid image URL");
    };
    if !allowed_source_image_url(&url) {
        return message(StatusCode::FORBIDDEN, "Image host is not allowed");
    }
    let upstream = match state.http_client.get(url).send().await {
        Ok(response) if response.status().is_success() => response,
        _ => return message(StatusCode::BAD_GATEWAY, "Source image could not be fetched"),
    };
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if !content_type.to_ascii_lowercase().starts_with("image/") {
        return message(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Source did not return an image",
        );
    }
    if upstream
        .content_length()
        .is_some_and(|length| length > MAX_SOURCE_IMAGE_BYTES as u64)
    {
        return message(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Source image exceeds the cacheable size",
        );
    }
    let mut bytes = Vec::with_capacity(
        upstream
            .content_length()
            .unwrap_or_default()
            .min(MAX_SOURCE_IMAGE_BYTES as u64) as usize,
    );
    let mut upstream = upstream;
    loop {
        match upstream.chunk().await {
            Ok(Some(chunk))
                if bytes.len().saturating_add(chunk.len()) <= MAX_SOURCE_IMAGE_BYTES =>
            {
                bytes.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => {
                return message(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Source image exceeds the cacheable size",
                );
            }
            Ok(None) => break,
            Err(_) => return message(StatusCode::BAD_GATEWAY, "Source image could not be fetched"),
        }
    }
    let content_length = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, s-maxage=31536000, stale-while-revalidate=86400"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    response
}

async fn site_board(
    State(state): State<AppState>,
    Path(menu_no): Path<String>,
    Query(query): Query<SitePageQuery>,
) -> Response {
    let page = query.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = query.per_page.unwrap_or(12).clamp(1, 100);
    let offset = (page - 1) * per_page;
    let rows = sqlx::query_scalar::<_, serde_json::Value>(
        &format!("SELECT jsonb_build_object('menu_no', payload->'menu_no', 'bno', payload->'bno', 'title', payload->'title', 'metadata_text', payload->'metadata_text', 'images', payload->'images') FROM site_articles WHERE menu_no = $1 AND {PUBLIC_CONTENT} ORDER BY sort_order ASC LIMIT $2 OFFSET $3"),
    )
    .bind(&menu_no)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await;
    let total = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*) FROM site_articles WHERE menu_no = $1 AND {PUBLIC_CONTENT}"
    ))
    .bind(&menu_no)
    .fetch_one(&state.db)
    .await;
    match (rows, total) {
        (Ok(items), Ok(total)) => Json(
            serde_json::json!({"items": items, "page": page, "per_page": per_page, "total": total}),
        )
        .into_response(),
        _ => message(StatusCode::INTERNAL_SERVER_ERROR, "Content lookup failed"),
    }
}

async fn site_article(
    State(state): State<AppState>,
    Path((menu_no, bno)): Path<(String, String)>,
) -> Response {
    match sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "SELECT payload FROM site_articles WHERE menu_no = $1 AND bno = $2 AND {PUBLIC_CONTENT}"
    ))
    .bind(menu_no)
    .bind(bno)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => message(StatusCode::NOT_FOUND, "Article not found"),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "Content lookup failed"),
    }
}

async fn import_site(State(state): State<AppState>, Json(input): Json<SiteImport>) -> Response {
    if input.pages.len() + input.articles.len() > 20 {
        return message(
            StatusCode::BAD_REQUEST,
            "Import batches are limited to 20 records",
        );
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return message(StatusCode::INTERNAL_SERVER_ERROR, "Import could not start"),
    };
    for page in &input.pages {
        let Some(menu_no) = page.get("menu_no").and_then(serde_json::Value::as_str) else {
            return message(StatusCode::BAD_REQUEST, "Page menu_no is required");
        };
        let Some(title) = page.get("title").and_then(serde_json::Value::as_str) else {
            return message(StatusCode::BAD_REQUEST, "Page title is required");
        };
        if sqlx::query("INSERT INTO site_pages (menu_no, title, payload) VALUES ($1, $2, $3) ON CONFLICT (menu_no) DO UPDATE SET title = EXCLUDED.title, payload = EXCLUDED.payload")
            .bind(menu_no).bind(title).bind(page).execute(&mut *tx).await.is_err() {
            return message(StatusCode::INTERNAL_SERVER_ERROR, "Page import failed");
        }
    }
    for article in &input.articles {
        let (Some(menu_no), Some(bno)) = (
            article.get("menu_no").and_then(serde_json::Value::as_str),
            article.get("bno").and_then(serde_json::Value::as_str),
        ) else {
            return message(
                StatusCode::BAD_REQUEST,
                "Article menu_no and bno are required",
            );
        };
        let sort_order = article
            .get("sort_order")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if sqlx::query("INSERT INTO site_articles (menu_no, bno, sort_order, payload) VALUES ($1, $2, $3, $4) ON CONFLICT (menu_no, bno) DO UPDATE SET sort_order = EXCLUDED.sort_order, payload = EXCLUDED.payload")
            .bind(menu_no).bind(bno).bind(sort_order).bind(article).execute(&mut *tx).await.is_err() {
            return message(StatusCode::INTERNAL_SERVER_ERROR, "Article import failed");
        }
    }
    if tx.commit().await.is_err() {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "Import could not finish");
    }
    Json(serde_json::json!({"pages": input.pages.len(), "articles": input.articles.len()}))
        .into_response()
}

pub(super) fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/site/pages/{menu_no}", get(site_page))
        .route("/api/site/image", get(proxy_site_image))
        .route("/api/site/boards/{menu_no}", get(site_board))
        .route("/api/site/articles/{menu_no}/{bno}", get(site_article))
}

pub(super) fn admin_routes() -> Router<AppState> {
    Router::new().route("/api/admin/site-import", post(import_site))
}
