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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
    if !["공지사항", "가정통신문", "학교소식", "학교앨범"].contains(&input.category.trim())
    {
        return Err("게시판 분류를 선택해 주세요.".into());
    }
    if input.title.trim().is_empty() || input.title.chars().count() > 120 {
        return Err("제목은 1자 이상 120자 이하로 입력해 주세요.".into());
    }
    if input.body.trim().is_empty() || input.body.chars().count() > 20_000 {
        return Err("내용은 1자 이상 20,000자 이하로 입력해 주세요.".into());
    }
    Ok(())
}

async fn initialize_db(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS notices (id TEXT PRIMARY KEY, created_at BIGINT NOT NULL, payload JSONB NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at BIGINT NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, attempted_at BIGINT NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS site_pages (menu_no TEXT PRIMARY KEY, title TEXT NOT NULL, payload JSONB NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS site_articles (menu_no TEXT NOT NULL, bno TEXT NOT NULL, sort_order BIGINT NOT NULL, payload JSONB NOT NULL, PRIMARY KEY (menu_no, bno))").execute(db).await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS site_articles_order_idx ON site_articles (menu_no, sort_order)",
    )
    .execute(db)
    .await?;
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

async fn proxy_site_image(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    const ALLOWED_HOSTS: [&str; 16] = [
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
    let Some(raw_url) = query.get("url") else {
        return message(StatusCode::BAD_REQUEST, "Image URL is required");
    };
    let Ok(url) = reqwest::Url::parse(raw_url) else {
        return message(StatusCode::BAD_REQUEST, "Invalid image URL");
    };
    if !["http", "https"].contains(&url.scheme())
        || !ALLOWED_HOSTS.contains(&url.host_str().unwrap_or_default())
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.port().is_some()
            && !(url.scheme() == "https"
                && ((url.host_str() == Some("withschool.co.kr") && url.port() == Some(3187))
                    || (url.host_str() == Some("ggg.hs.kr") && url.port() == Some(535)))))
    {
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
        .is_some_and(|length| length > 20 * 1024 * 1024)
    {
        return message(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Source image exceeds the cacheable size",
        );
    }
    let content_length = upstream.content_length();
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
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
    if let Some(length) = content_length {
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            response.headers_mut().insert(header::CONTENT_LENGTH, value);
        }
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
    let terms = query_text
        .split_whitespace()
        .map(|term| term.trim_matches(|character: char| !character.is_alphanumeric()))
        .filter(|term| term.chars().count() >= 2)
        .take(8)
        .map(str::to_owned)
        .collect::<Vec<_>>();
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
                .filter(|n| n.published && query.get("category").is_none_or(|c| c == &n.category))
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
    let now = now_seconds();
    let notice = Notice {
        id: Uuid::new_v4().to_string(),
        category: input.category.trim().into(),
        title: input.title.trim().into(),
        body: input.body.trim().into(),
        published: input.published,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };
    match sqlx::query("INSERT INTO notices (id, created_at, payload) VALUES ($1, $2, $3)")
        .bind(&notice.id)
        .bind(now)
        .bind(serde_json::to_value(&notice).unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => (StatusCode::CREATED, Json(notice)).into_response(),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "저장하지 못했습니다."),
    }
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
    let old = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(value)) => match serde_json::from_value::<Notice>(value) {
            Ok(notice) => notice,
            Err(_) => {
                return message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "게시물을 읽지 못했습니다.",
                );
            }
        },
        Ok(None) => return message(StatusCode::NOT_FOUND, "게시물을 찾을 수 없습니다."),
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "게시물을 읽지 못했습니다.",
            );
        }
    };
    let notice = Notice {
        id: id.clone(),
        category: input.category.trim().into(),
        title: input.title.trim().into(),
        body: input.body.trim().into(),
        published: input.published,
        created_at: old.created_at,
        updated_at: now_seconds().to_string(),
    };
    match sqlx::query("UPDATE notices SET payload = $2 WHERE id = $1")
        .bind(id)
        .bind(serde_json::to_value(&notice).unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => Json(notice).into_response(),
        Ok(_) => message(StatusCode::NOT_FOUND, "게시물을 찾을 수 없습니다."),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "수정하지 못했습니다."),
    }
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
