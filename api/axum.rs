// GitHub Pages 학교 홈페이지용 Axum 관리자 API 서버리스 진입점
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, postgres::PgPoolOptions};
use std::{
    collections::HashMap,
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use uuid::Uuid;
use vercel_runtime::Error;
use vercel_runtime::axum::VercelLayer;

const SESSION_COOKIE: &str = "dkis_admin";
const SESSION_SECONDS: i64 = 8 * 60 * 60;
const MAX_SOURCE_IMAGE_BYTES: usize = 20 * 1024 * 1024;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();
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

#[derive(Clone)]
struct AppState {
    db: PgPool,
    http_client: reqwest::Client,
    username: Option<String>,
    password_hash: Option<String>,
    secure_cookie: bool,
    same_site: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Notice {
    id: String,
    category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    menu_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image_url: Option<String>,
    title: String,
    body: String,
    published: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct NoticeInput {
    category: String,
    #[serde(default)]
    menu_id: Option<String>,
    #[serde(default)]
    image_data: Option<String>,
    #[serde(default)]
    remove_image: bool,
    title: String,
    body: String,
    published: bool,
}

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

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
}

#[derive(Serialize)]
struct ChatMatch {
    title: String,
    excerpt: String,
    url: String,
    kind: &'static str,
    #[serde(skip)]
    score: usize,
}

#[derive(Serialize)]
struct Message {
    message: String,
}

fn message(status: StatusCode, text: impl Into<String>) -> Response {
    (
        status,
        Json(Message {
            message: text.into(),
        }),
    )
        .into_response()
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == SESSION_COOKIE && !value.is_empty()).then(|| value.to_owned())
        })
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

async fn session_user(headers: &HeaderMap, state: &AppState) -> Option<String> {
    let token = cookie_token(headers)?;
    sqlx::query_scalar::<_, String>(
        "SELECT username FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2",
    )
    .bind(token_hash(&token))
    .bind(now_seconds())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
}

async fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<String, Response> {
    if state.username.is_none() || state.password_hash.is_none() {
        return Err(message(
            StatusCode::SERVICE_UNAVAILABLE,
            "서버에 관리자 계정이 설정되지 않았습니다.",
        ));
    }
    session_user(headers, state)
        .await
        .ok_or_else(|| message(StatusCode::UNAUTHORIZED, "관리자 로그인이 필요합니다."))
}

fn set_session_cookie(response: &mut Response, token: &str, state: &AppState) {
    let secure = if state.secure_cookie { "; Secure" } else { "" };
    let value = format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite={}{secure}",
        state.same_site
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

fn clear_session_cookie(response: &mut Response, state: &AppState) {
    let secure = if state.secure_cookie { "; Secure" } else { "" };
    let value = format!(
        "{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite={}{secure}",
        state.same_site
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

fn validate_notice(input: &NoticeInput) -> Result<(), String> {
    let valid_menu_ids = [
        "40", "41", "42", "44", "45", "46", "47", "49", "70", "79", "81", "87", "88", "94", "96",
        "103", "113", "129", "130", "131", "182", "183", "184", "185", "187", "189", "190", "191",
        "193", "194", "195", "196", "200", "201", "202", "203", "204", "205", "206",
    ];
    if input.category.trim().is_empty()
        || input.category.chars().count() > 80
        || input
            .menu_id
            .as_deref()
            .is_some_and(|id| !valid_menu_ids.contains(&id))
    {
        return Err("Choose a valid board and category.".into());
    }
    if input.title.trim().is_empty() || input.title.chars().count() > 120 {
        return Err("Title must contain 1 to 120 characters.".into());
    }
    if input.body.trim().is_empty() || input.body.chars().count() > 20_000 {
        return Err("Body must contain 1 to 20,000 characters.".into());
    }
    if input
        .image_data
        .as_ref()
        .is_some_and(|image| image.len() > 1_450_000)
    {
        return Err("Image data exceeds the upload limit.".into());
    }
    Ok(())
}

fn decode_notice_image(value: &str) -> Result<(String, Vec<u8>), String> {
    let (metadata, encoded) = value.split_once(',').ok_or("Invalid image data.")?;
    let content_type = match metadata {
        "data:image/jpeg;base64" => "image/jpeg",
        "data:image/png;base64" => "image/png",
        "data:image/webp;base64" => "image/webp",
        _ => return Err("Only JPG, PNG, and WEBP images are allowed.".into()),
    };
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "Invalid base64 image data.")?;
    let valid_signature = match content_type {
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/webp" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        _ => false,
    };
    if bytes.is_empty() || bytes.len() > 1_048_576 || !valid_signature {
        return Err("Image is invalid or exceeds 1 MB.".into());
    }
    Ok((content_type.into(), bytes))
}

async fn initialize_db(db: &PgPool) -> Result<(), Error> {
    MIGRATOR.run(db).await?;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= $1")
        .bind(now_seconds())
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM login_attempts WHERE attempted_at <= $1")
        .bind(now_seconds() - 600)
        .execute(db)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notices")
        .fetch_one(db)
        .await?;
    if count == 0 {
        let now = now_seconds().to_string();
        for (category, title, body) in [
            (
                "공지사항",
                "학교 교육활동 안내",
                "학교 교육활동 안내 예시입니다.",
            ),
            (
                "공지사항",
                "신입생 입학 안내",
                "입학 안내 예시입니다. 실제 일정은 학교 공식 홈페이지에서 확인하세요.",
            ),
            (
                "가정통신문",
                "안전 및 건강 관리 안내",
                "가정통신문 예시입니다.",
            ),
        ] {
            let notice = Notice {
                id: Uuid::new_v4().to_string(),
                category: category.into(),
                menu_id: None,
                image_url: None,
                title: title.into(),
                body: body.into(),
                published: true,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            let id = notice.id.clone();
            sqlx::query("INSERT INTO notices (id, created_at, payload) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(id).bind(now.parse::<i64>().unwrap_or_default()).bind(serde_json::to_value(notice).unwrap_or_default()).execute(db).await?;
        }
    }
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok", "service":"dkischool-api"}))
}

async fn site_page(State(state): State<AppState>, Path(menu_no): Path<String>) -> Response {
    match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM site_pages WHERE menu_no = $1",
    )
    .bind(menu_no)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => message(StatusCode::NOT_FOUND, "Page not found"),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "Content lookup failed"),
    }
}

fn allowed_source_image_url(url: &reqwest::Url) -> bool {
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
        "SELECT jsonb_build_object('menu_no', payload->'menu_no', 'bno', payload->'bno', 'title', payload->'title', 'metadata_text', payload->'metadata_text', 'images', payload->'images') FROM site_articles WHERE menu_no = $1 ORDER BY sort_order ASC LIMIT $2 OFFSET $3",
    )
    .bind(&menu_no)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await;
    let total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM site_articles WHERE menu_no = $1")
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
    match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM site_articles WHERE menu_no = $1 AND bno = $2",
    )
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

fn html_text(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    let mut in_tag = false;
    for character in value.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text.replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn excerpt(value: &str, terms: &[String]) -> String {
    let text = html_text(value);
    let offset = terms
        .iter()
        .filter_map(|term| text.to_lowercase().find(&term.to_lowercase()))
        .min()
        .map(|byte_offset| text[..byte_offset].chars().count().saturating_sub(80))
        .unwrap_or(0);
    let chars = text.chars().collect::<Vec<_>>();
    let end = (offset + 320).min(chars.len());
    let excerpt = chars[offset..end].iter().collect::<String>();
    format!(
        "{}{}{}",
        if offset > 0 { "…" } else { "" },
        excerpt,
        if end < chars.len() { "…" } else { "" }
    )
}

async fn matching_content(
    db: &PgPool,
    table: &'static str,
    terms: &[String],
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(format!("SELECT payload FROM {table} WHERE ("));
    for (index, term) in terms.iter().enumerate() {
        if index > 0 {
            query.push(" OR ");
        }
        query
            .push("payload::text ILIKE ")
            .push_bind(format!("%{term}%"));
    }
    query.push(")");
    if table == "site_pages" {
        query.push(" AND COALESCE(payload->>'access_status', '') <> 'restricted'");
    }
    query.push(" ORDER BY (");
    for (index, term) in terms.iter().enumerate() {
        if index > 0 {
            query.push(" + ");
        }
        query
            .push("CASE WHEN payload->>'title' ILIKE ")
            .push_bind(format!("%{term}%"))
            .push(" THEN 10 ELSE 0 END + CASE WHEN payload->>'body_html' ILIKE ")
            .push_bind(format!("%{term}%"))
            .push(" THEN 1 ELSE 0 END");
    }
    query
        .push(") DESC LIMIT 8")
        .build_query_scalar::<serde_json::Value>()
        .fetch_all(db)
        .await
}

async fn site_chat(State(state): State<AppState>, Json(input): Json<ChatRequest>) -> Response {
    let query_text = input.message.trim();
    if query_text.chars().count() < 2 || query_text.chars().count() > 300 {
        return message(
            StatusCode::BAD_REQUEST,
            "질문은 2자 이상 300자 이하로 입력해 주세요.",
        );
    }
    let mut terms = query_text
        .split_whitespace()
        .map(|term| term.trim_matches(|character: char| !character.is_alphanumeric()))
        .filter(|term| term.chars().count() >= 2)
        .take(8)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let contact_intent = ["연락처", "전화번호", "전화", "주소", "오시는길", "위치"]
        .iter()
        .any(|term| query_text.replace(' ', "").contains(term));
    if terms.len() > 1
        && terms
            .iter()
            .any(|term| !matches!(term.as_str(), "학교" | "안내" | "문의" | "정보"))
    {
        terms.retain(|term| !matches!(term.as_str(), "학교" | "안내" | "문의" | "정보"));
    }
    if contact_intent {
        for term in ["연락처", "전화번호", "전화", "주소", "오시는길"] {
            if !terms.iter().any(|existing| existing == term) {
                terms.push(term.to_owned());
            }
        }
    }
    if terms.is_empty() {
        return Json(serde_json::json!({"matches": []})).into_response();
    }
    let pages = matching_content(&state.db, "site_pages", &terms).await;
    let articles = matching_content(&state.db, "site_articles", &terms).await;
    let (Ok(pages), Ok(articles)) = (pages, articles) else {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "학교 자료 검색에 실패했습니다.",
        );
    };
    let mut matches = Vec::new();
    for payload in pages {
        if payload
            .get("access_status")
            .and_then(serde_json::Value::as_str)
            == Some("restricted")
        {
            continue;
        }
        let Some(menu_no) = payload.get("menu_no").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let raw_title = payload
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("학교 안내");
        let title = if raw_title.chars().any(char::is_alphanumeric) {
            raw_title
        } else {
            "학교 홈페이지"
        };
        let body = payload
            .get("body_html")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let excerpt = excerpt(body, &terms);
        let title_lower = title.to_lowercase();
        let body_lower = body.to_lowercase();
        let score = terms
            .iter()
            .map(|term| {
                usize::from(title_lower.contains(&term.to_lowercase())) * 10
                    + usize::from(body_lower.contains(&term.to_lowercase()))
            })
            .sum();
        matches.push(ChatMatch {
            title: title.to_owned(),
            excerpt,
            url: format!("#/page/{menu_no}"),
            kind: "page",
            score,
        });
    }
    for payload in articles {
        let (Some(menu_no), Some(bno)) = (
            payload.get("menu_no").and_then(serde_json::Value::as_str),
            payload.get("bno").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let title = payload
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("게시물");
        let body = payload
            .get("body_html")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let excerpt = excerpt(body, &terms);
        let title_lower = title.to_lowercase();
        let body_lower = body.to_lowercase();
        let score = terms
            .iter()
            .map(|term| {
                usize::from(title_lower.contains(&term.to_lowercase())) * 10
                    + usize::from(body_lower.contains(&term.to_lowercase()))
            })
            .sum();
        matches.push(ChatMatch {
            title: title.to_owned(),
            excerpt,
            url: format!("#/page/{menu_no}?menu_no={menu_no}&bno={bno}&board_mode=view"),
            kind: "article",
            score,
        });
    }
    if contact_intent && !matches.iter().any(|item| item.url == "#/page/20") {
        if let Ok(Some(payload)) = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT payload FROM site_pages WHERE menu_no = '20'",
        )
        .fetch_optional(&state.db)
        .await
        {
            let title = payload
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("오시는 길");
            let body = payload
                .get("body_html")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            matches.push(ChatMatch {
                title: title.to_owned(),
                excerpt: excerpt(body, &terms),
                url: "#/page/20".to_owned(),
                kind: "page",
                score: 30,
            });
        }
    }
    matches.sort_by(|left, right| right.score.cmp(&left.score));
    matches.truncate(8);
    Json(serde_json::json!({"matches": matches})).into_response()
}

async fn import_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SiteImport>,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
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

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> Response {
    let (Some(username), Some(hash)) = (state.username.as_ref(), state.password_hash.as_ref())
    else {
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            "서버에 관리자 계정이 설정되지 않았습니다.",
        );
    };
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("unknown")
        .trim()
        .to_owned();
    let _ = sqlx::query("DELETE FROM login_attempts WHERE attempted_at <= $1")
        .bind(now_seconds() - 600)
        .execute(&state.db)
        .await;
    let attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = $1 AND attempted_at > $2",
    )
    .bind(&ip)
    .bind(now_seconds() - 600)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    if attempts >= 5 {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.",
        );
    }
    let _ = sqlx::query("INSERT INTO login_attempts (ip, attempted_at) VALUES ($1, $2)")
        .bind(&ip)
        .bind(now_seconds())
        .execute(&state.db)
        .await;
    let verified = PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(input.password.as_bytes(), &parsed)
            .is_ok()
    });
    if input.username != *username || !verified {
        return message(
            StatusCode::UNAUTHORIZED,
            "아이디 또는 비밀번호를 확인해 주세요.",
        );
    }
    let _ = sqlx::query("DELETE FROM login_attempts WHERE ip = $1")
        .bind(ip)
        .execute(&state.db)
        .await;
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let expires = now_seconds() + SESSION_SECONDS;
    if sqlx::query(
        "INSERT INTO admin_sessions (token_hash, username, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash(&token))
    .bind(username)
    .bind(expires)
    .execute(&state.db)
    .await
    .is_err()
    {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "로그인 세션을 저장하지 못했습니다.",
        );
    }
    let mut response = Json(Message {
        message: "로그인했습니다.".into(),
    })
    .into_response();
    set_session_cookie(&mut response, &token, &state);
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        let _ = sqlx::query("DELETE FROM admin_sessions WHERE token_hash = $1")
            .bind(token_hash(&token))
            .execute(&state.db)
            .await;
    }
    let mut response = Json(Message {
        message: "로그아웃했습니다.".into(),
    })
    .into_response();
    clear_session_cookie(&mut response, &state);
    response
}

async fn admin_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match session_user(&headers, &state).await {
        Some(username) => {
            Json(serde_json::json!({"authenticated":true,"username":username})).into_response()
        }
        None if state.username.is_none() || state.password_hash.is_none() => message(
            StatusCode::SERVICE_UNAVAILABLE,
            "서버에 관리자 계정이 설정되지 않았습니다.",
        ),
        None => message(StatusCode::UNAUTHORIZED, "관리자 로그인이 필요합니다."),
    }
}

async fn read_notices(db: &PgPool) -> Result<Vec<Notice>, sqlx::Error> {
    let values = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?;
    Ok(values
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect())
}

async fn list_notices(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match read_notices(&state.db).await {
        Ok(notices) => Json(
            notices
                .into_iter()
                .filter(|n| {
                    n.published
                        && if let Some(menu_id) = query.get("menu_id") {
                            n.menu_id.as_deref() == Some(menu_id)
                                || (n.menu_id.is_none()
                                    && query
                                        .get("category")
                                        .is_some_and(|category| category == &n.category))
                        } else {
                            query
                                .get("category")
                                .is_none_or(|category| category == &n.category)
                        }
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "게시물을 불러오지 못했습니다.",
        ),
    }
}

async fn get_notice(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match sqlx::query_scalar::<_, serde_json::Value>("SELECT payload FROM notices WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(value)) => match serde_json::from_value::<Notice>(value) {
            Ok(n) if n.published => Json(n).into_response(),
            _ => message(StatusCode::NOT_FOUND, "게시물을 찾을 수 없습니다."),
        },
        Ok(None) => message(StatusCode::NOT_FOUND, "게시물을 찾을 수 없습니다."),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "게시물을 불러오지 못했습니다.",
        ),
    }
}

async fn notice_image(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT content_type, data FROM notice_images WHERE notice_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some((content_type, bytes))) => {
            let mut response = Body::from(bytes).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            );
            response
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "이미지를 불러오지 못했습니다.",
        ),
    }
}

async fn admin_notices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    match read_notices(&state.db).await {
        Ok(notices) => Json(notices).into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "게시물을 불러오지 못했습니다.",
        ),
    }
}

async fn create_notice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NoticeInput>,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    if let Err(error) = validate_notice(&input) {
        return message(StatusCode::BAD_REQUEST, error);
    }
    let image = match input
        .image_data
        .as_deref()
        .map(decode_notice_image)
        .transpose()
    {
        Ok(image) => image,
        Err(error) => return message(StatusCode::BAD_REQUEST, error),
    };
    let now = now_seconds();
    let id = Uuid::new_v4().to_string();
    let notice = Notice {
        id: id.clone(),
        category: input.category.trim().into(),
        menu_id: input.menu_id,
        image_url: image.as_ref().map(|_| format!("/notices/{id}/image")),
        title: input.title.trim().into(),
        body: input.body.trim().into(),
        published: input.published,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    };
    if sqlx::query("INSERT INTO notices (id, created_at, payload) VALUES ($1, $2, $3)")
        .bind(&notice.id)
        .bind(now)
        .bind(serde_json::to_value(&notice).unwrap_or_default())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be saved.",
        );
    }
    if let Some((content_type, bytes)) = image {
        if sqlx::query(
            "INSERT INTO notice_images (notice_id, content_type, data) VALUES ($1, $2, $3)",
        )
        .bind(&notice.id)
        .bind(content_type)
        .bind(bytes)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    }
    if tx.commit().await.is_err() {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be saved.",
        );
    }
    (StatusCode::CREATED, Json(notice)).into_response()
}

async fn update_notice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<NoticeInput>,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    if let Err(error) = validate_notice(&input) {
        return message(StatusCode::BAD_REQUEST, error);
    }
    let image = match input
        .image_data
        .as_deref()
        .map(decode_notice_image)
        .transpose()
    {
        Ok(image) => image,
        Err(error) => return message(StatusCode::BAD_REQUEST, error),
    };
    let old_value = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    };
    let old = match serde_json::from_value::<Notice>(old_value) {
        Ok(notice) => notice,
        Err(_) => return message(StatusCode::INTERNAL_SERVER_ERROR, "Invalid notice data."),
    };
    let image_url = if image.is_some() {
        Some(format!("/notices/{id}/image"))
    } else if input.remove_image {
        None
    } else {
        old.image_url.clone()
    };
    let notice = Notice {
        id: id.clone(),
        category: input.category.trim().into(),
        menu_id: input.menu_id,
        image_url,
        title: input.title.trim().into(),
        body: input.body.trim().into(),
        published: input.published,
        created_at: old.created_at,
        updated_at: now_seconds().to_string(),
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    };
    if sqlx::query("UPDATE notices SET payload = $2 WHERE id = $1")
        .bind(&id)
        .bind(serde_json::to_value(&notice).unwrap_or_default())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be saved.",
        );
    }
    if let Some((content_type, bytes)) = image {
        if sqlx::query("INSERT INTO notice_images (notice_id, content_type, data) VALUES ($1, $2, $3) ON CONFLICT (notice_id) DO UPDATE SET content_type = EXCLUDED.content_type, data = EXCLUDED.data")
            .bind(&id).bind(content_type).bind(bytes).execute(&mut *tx).await.is_err() {
            return message(StatusCode::INTERNAL_SERVER_ERROR, "The request could not be saved.");
        }
    } else if input.remove_image {
        if sqlx::query("DELETE FROM notice_images WHERE notice_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    }
    if tx.commit().await.is_err() {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be saved.",
        );
    }
    Json(notice).into_response()
}

async fn delete_notice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    match sqlx::query("DELETE FROM notices WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => message(StatusCode::NOT_FOUND, "게시물을 찾을 수 없습니다."),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "삭제하지 못했습니다."),
    }
}

async fn app() -> Result<Router, Error> {
    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    initialize_db(&db).await?;
    let same_site = env::var("COOKIE_SAME_SITE").unwrap_or_else(|_| "None".into());
    let secure_cookie =
        env::var("COOKIE_SECURE").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !["Strict", "Lax", "None"].contains(&same_site.as_str())
        || (same_site == "None" && !secure_cookie)
    {
        return Err("COOKIE_SAME_SITE=None requires COOKIE_SECURE=true; allowed values are Strict, Lax, and None".into());
    }
    let state = AppState {
        db,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || !allowed_source_image_url(attempt.url()) {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()?,
        username: env::var("ADMIN_USERNAME").ok().filter(|v| !v.is_empty()),
        password_hash: env::var("ADMIN_PASSWORD")
            .ok()
            .filter(|v| v.chars().count() >= 12)
            .map(|password| {
                use argon2::PasswordHasher;
                use argon2::password_hash::SaltString;
                Argon2::default()
                    .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                    .map(|h| h.to_string())
                    .unwrap_or_default()
            }),
        secure_cookie,
        same_site,
    };
    let mut router = Router::new()
        .route("/api/health", get(health))
        .route("/api/site/pages/{menu_no}", get(site_page))
        .route("/api/site/image", get(proxy_site_image))
        .route("/api/site/boards/{menu_no}", get(site_board))
        .route("/api/site/articles/{menu_no}/{bno}", get(site_article))
        .route("/api/site/chat", post(site_chat))
        .route("/api/admin/site-import", post(import_site))
        .route("/api/notices", get(list_notices))
        .route("/api/notices/{id}", get(get_notice))
        .route("/api/notices/{id}/image", get(notice_image))
        .route("/api/admin/login", post(login))
        .route("/api/admin/logout", post(logout))
        .route("/api/admin/session", get(admin_session))
        .route("/api/admin/notices", get(admin_notices).post(create_notice))
        .route(
            "/api/admin/notices/{id}",
            put(update_notice).delete(delete_notice),
        )
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .with_state(state);
    if let Ok(origin) = env::var("FRONTEND_ORIGIN") {
        let origin = origin.parse::<HeaderValue>()?;
        router = router.layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([header::CONTENT_TYPE])
                .allow_credentials(true),
        );
    }
    Ok(router)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let service = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(app().await?);
    vercel_runtime::run(service).await
}

#[cfg(test)]
mod tests {
    use super::{
        NoticeInput, STANDARD, allowed_source_image_url, decode_notice_image, validate_notice,
    };
    use base64::Engine;

    fn valid_notice(menu_id: Option<&str>) -> NoticeInput {
        NoticeInput {
            category: "공지사항".into(),
            menu_id: menu_id.map(str::to_owned),
            image_data: None,
            remove_image: false,
            title: "Test title".into(),
            body: "Test body".into(),
            published: true,
        }
    }

    #[test]
    fn accepts_a_migrated_board_and_rejects_unknown_board_ids() {
        assert!(validate_notice(&valid_notice(Some("47"))).is_ok());
        assert!(validate_notice(&valid_notice(Some("999"))).is_err());
    }

    #[test]
    fn accepts_only_supported_images_with_matching_file_signatures() {
        let png = STANDARD.encode(b"\x89PNG\r\n\x1a\n");
        let (content_type, bytes) = decode_notice_image(&format!("data:image/png;base64,{png}"))
            .expect("valid PNG signature should be accepted");
        assert_eq!(content_type, "image/png");
        assert_eq!(bytes, b"\x89PNG\r\n\x1a\n");
        assert!(decode_notice_image("data:image/svg+xml;base64,PHN2Zz4=").is_err());
        assert!(decode_notice_image("data:image/png;base64,dGVzdA==").is_err());
    }

    #[test]
    fn image_proxy_allows_only_listed_hosts_and_ports() {
        assert!(allowed_source_image_url(
            &reqwest::Url::parse("https://dkischool.org/image.jpg").unwrap()
        ));
        assert!(allowed_source_image_url(
            &reqwest::Url::parse("https://withschool.co.kr:3187/image.jpg").unwrap()
        ));
        assert!(!allowed_source_image_url(
            &reqwest::Url::parse("https://example.com/image.jpg").unwrap()
        ));
        assert!(!allowed_source_image_url(
            &reqwest::Url::parse("http://dkischool.org:8080/image.jpg").unwrap()
        ));
        assert!(!allowed_source_image_url(
            &reqwest::Url::parse("https://user@dkischool.org/image.jpg").unwrap()
        ));
    }
}
