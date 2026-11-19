// GitHub Pages 학교 홈페이지용 Axum 관리자 API 서버리스 진입점
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    body::Body,
    extract::{Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
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
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use uuid::Uuid;
use vercel_runtime::Error;
use vercel_runtime::axum::VercelLayer;

const PUBLIC_CONTENT: &str = "COALESCE(payload->>'access_status', '') <> 'restricted'";
const SESSION_COOKIE: &str = "dkis_admin";
const SESSION_SECONDS: i64 = 8 * 60 * 60;
const MAX_SOURCE_IMAGE_BYTES: usize = 20 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 3 * 1024 * 1024;
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
    frontend_origin: Option<HeaderValue>,
    password_workers: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Notice {
    id: String,
    category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    menu_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image_url: Option<String>,
    #[serde(default)]
    attachments: Vec<NoticeAttachment>,
    title: String,
    body: String,
    published: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NoticeAttachment {
    id: String,
    filename: String,
    content_type: String,
    size_bytes: usize,
    url: String,
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
    visitor: Option<String>,
}

#[derive(Serialize)]
struct ChatMatch {
    title: String,
    excerpt: String,
    url: String,
    kind: &'static str,
    #[serde(skip)]
    score: i32,
    #[serde(skip)]
    likes: i64,
    #[serde(skip)]
    date: Option<String>,
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

fn validate_attachment(filename: &str, bytes: &[u8]) -> Result<&'static str, String> {
    if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err("Attachments must be smaller than 3 MB.".into());
    }
    let extension = filename
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .ok_or("This file type is not supported.")?;
    let valid = match extension.as_str() {
        "jpg" | "jpeg" if bytes.starts_with(&[0xff, 0xd8, 0xff]) => "image/jpeg",
        "png" if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => "image/png",
        "webp" if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") => "image/webp",
        "gif" if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") => "image/gif",
        "pdf" if bytes.starts_with(b"%PDF-") => "application/pdf",
        "hwp" if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") => "application/x-hwp",
        "hwpx" | "docx" | "xlsx" | "pptx" if bytes.starts_with(b"PK\x03\x04") => {
            match extension.as_str() {
                "hwpx" => "application/vnd.hancom.hwpx",
                "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                _ => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            }
        }
        "doc" if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") => "application/msword",
        "xls" if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") => {
            "application/vnd.ms-excel"
        }
        "ppt" if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") => {
            "application/vnd.ms-powerpoint"
        }
        "txt" if std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0) => {
            "text/plain; charset=utf-8"
        }
        _ => return Err("File type does not match its contents or is not supported.".into()),
    };
    Ok(valid)
}

fn safe_attachment_filename(value: &str) -> Option<String> {
    let filename = value.rsplit(['/', '\\']).next()?.trim();
    if filename.is_empty()
        || filename.chars().count() > 180
        || filename.chars().any(char::is_control)
    {
        return None;
    }
    Some(filename.to_owned())
}

fn encode_header_filename(filename: &str) -> String {
    filename
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
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
    sqlx::query("DELETE FROM chat_request_limits WHERE minute < $1")
        .bind(now_seconds() / 60 - 1)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM chat_search_receipts WHERE expires_at <= $1")
        .bind(now_seconds())
        .execute(db)
        .await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok", "service":"dkischool-api"}))
}

async fn readiness(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"status": "ready"})).into_response(),
        Err(error) => {
            eprintln!("Database readiness check failed: {error}");
            message(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
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

fn normalized_search_terms(query: &str) -> Vec<String> {
    let particles = [
        "에서는",
        "으로",
        "에서",
        "에게",
        "부터",
        "까지",
        "은",
        "는",
        "이",
        "가",
        "을",
        "를",
        "에",
        "의",
        "도",
        "만",
        "와",
        "과",
        "로",
    ];
    let mut terms = Vec::new();
    for raw_term in query.split_whitespace() {
        let term = raw_term.trim_matches(|character: char| !character.is_alphanumeric());
        if term.chars().count() < 2 {
            continue;
        }
        if !terms.iter().any(|existing| existing == term) {
            terms.push(term.to_owned());
        }
        for particle in particles {
            if let Some(stem) = term.strip_suffix(particle)
                && stem.chars().count() >= 2
            {
                if !terms.iter().any(|existing| existing == stem) {
                    terms.push(stem.to_owned());
                }
                break;
            }
        }
        if terms.len() >= 8 {
            terms.truncate(8);
            break;
        }
    }
    terms
}

const SEARCH_DATE: &str = "replace(substring(payload->>'metadata_text' from '[0-9]{4}[-.][0-9]{2}[-.][0-9]{2}'), '.', '-')";

async fn matching_content(
    db: &PgPool,
    table: &'static str,
    terms: &[String],
    time_sensitive: bool,
    question_key: &str,
) -> Result<Vec<(serde_json::Value, Option<String>, i32, i64)>, sqlx::Error> {
    let url = if table == "site_pages" {
        "'#/page/' || menu_no"
    } else {
        "'#/page/' || menu_no || '?menu_no=' || menu_no || '&bno=' || bno || '&board_mode=view'"
    };
    let mut query =
        QueryBuilder::<Postgres>::new(format!("SELECT payload, {SEARCH_DATE} AS published_date, "));
    for (index, term) in terms.iter().enumerate() {
        if index > 0 {
            query.push(" + ");
        }
        query
            .push("CASE WHEN payload->>'title' ILIKE ")
            .push_bind(format!("%{term}%"))
            .push(" THEN 10 ELSE 0 END + CASE WHEN school_search_body(payload) ILIKE ")
            .push_bind(format!("%{term}%"))
            .push(" THEN 1 ELSE 0 END");
    }
    query.push(" AS score, ");
    if time_sensitive {
        query.push("0::bigint");
    } else {
        query
            .push("(SELECT count(*) FROM chat_likes WHERE question_key = ")
            .push_bind(question_key)
            .push(format!(" AND result_url = ({url}))"));
    }
    query.push(format!(" AS likes FROM {table} WHERE ("));
    for (index, term) in terms.iter().enumerate() {
        if index > 0 {
            query.push(" OR ");
        }
        query
            .push("(coalesce(payload->>'title', '') || ' ' || school_search_body(payload)) ILIKE ")
            .push_bind(format!("%{term}%"));
    }
    query
        .push(") AND ")
        .push(PUBLIC_CONTENT)
        .push(" ORDER BY score DESC, ");
    query.push(if time_sensitive {
        "published_date DESC NULLS LAST, "
    } else {
        "likes DESC, "
    });
    query
        .push(format!(r#"({url}) COLLATE "C" LIMIT 8"#))
        .build_query_as::<(serde_json::Value, Option<String>, i32, i64)>()
        .fetch_all(db)
        .await
}

fn chat_question_key(question: &str) -> String {
    let normalized = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    format!("{:x}", Sha256::digest(normalized.as_bytes()))
}

#[test]
fn chat_feedback_key_ignores_case_and_whitespace() {
    assert_eq!(
        chat_question_key("  DKIS   입학 "),
        chat_question_key("dkis 입학")
    );
    assert_ne!(
        chat_question_key("초등 입학"),
        chat_question_key("중등 입학")
    );
}

#[test]
fn chat_topics_use_only_public_labels() {
    assert_eq!(chat_topic("초등 전학 서류"), Some("입학 안내"));
    assert_eq!(chat_topic("등록금 얼마인가요"), Some("학비"));
    assert_eq!(chat_topic("오늘 점심"), Some("급식 식단"));
    assert_eq!(chat_topic("교무실 전화번호"), Some("학교 연락처"));
    assert_eq!(chat_topic("알려 드릴 개인 사정"), None);
}

fn chat_topic(question: &str) -> Option<&'static str> {
    [
        ("입학 안내", &["입학", "전학"][..]),
        ("학비", &["학비", "등록금", "수업료"][..]),
        ("급식 식단", &["급식", "식단", "점심"][..]),
        ("학교 연락처", &["연락처", "전화번호", "교무실 전화"][..]),
        ("학사 일정", &["학사 일정", "학사일정", "방학"][..]),
    ]
    .into_iter()
    .find(|(_, terms)| terms.iter().any(|term| question.contains(term)))
    .map(|(topic, _)| topic)
}

async fn admin_chat_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    let days = match query.get("days").map(String::as_str).unwrap_or("30") {
        "7" => 7,
        "30" => 30,
        "90" => 90,
        "all" => 0,
        _ => return message(StatusCode::BAD_REQUEST, "조회 기간을 다시 선택해 주세요."),
    };
    let rows = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT day::text, topic, searches, measured_searches, no_results FROM chat_topic_daily WHERE $1 = 0 OR day >= CURRENT_DATE - ($1 - 1) ORDER BY day DESC, topic",
    )
    .bind(days)
    .fetch_all(&state.db)
    .await;
    let Ok(rows) = rows else {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "채팅 통계를 불러오지 못했습니다.",
        );
    };
    let daily: Vec<_> = rows.into_iter().map(|(date, topic, searches, measured, no_results)| {
        serde_json::json!({"date": date, "topic": topic, "searches": searches, "measured": measured, "no_results": no_results})
    }).collect();
    let likes = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT votes.result_url, COALESCE(a.payload->>'title', p.payload->>'title', votes.result_url), votes.total
         FROM (SELECT result_url, COUNT(*) AS total FROM chat_likes GROUP BY result_url) votes
         LEFT JOIN site_articles a ON votes.result_url = '#/page/' || a.menu_no || '?menu_no=' || a.menu_no || '&bno=' || a.bno || '&board_mode=view'
         LEFT JOIN site_pages p ON votes.result_url = '#/page/' || p.menu_no
         WHERE a.menu_no IS NOT NULL OR p.menu_no IS NOT NULL
         ORDER BY votes.total DESC, votes.result_url LIMIT 10",
    ).fetch_all(&state.db).await;
    let Ok(likes) = likes else {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "도움됐어요 통계를 불러오지 못했습니다.",
        );
    };
    let helpful: Vec<_> = likes
        .into_iter()
        .map(|(url, title, count)| serde_json::json!({"url": url, "title": title, "count": count}))
        .collect();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(serde_json::json!({"daily": daily, "helpful": helpful})),
    )
        .into_response()
}

async fn popular_chat_topics(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, String>(
        "SELECT topic FROM chat_topic_daily WHERE day >= CURRENT_DATE - 29 GROUP BY topic ORDER BY SUM(searches) DESC, topic LIMIT 5"
    ).fetch_all(&state.db).await {
        Ok(topics) => Json(serde_json::json!({"topics": topics})).into_response(),
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "인기 질문을 불러오지 못했습니다."),
    }
}

#[derive(Deserialize)]
struct ChatFeedback {
    message: String,
    visitor: String,
    url: String,
    liked: bool,
}

async fn chat_request_limit(
    db: &PgPool,
    headers: &HeaderMap,
    scope: &str,
    limit: i32,
) -> Result<(), Response> {
    let minute = now_seconds() / 60;
    let count = sqlx::query_scalar::<_, i32>(
        "INSERT INTO chat_request_limits (scope, client_key, minute) VALUES ($1, $2, $3)
         ON CONFLICT (scope, client_key, minute) DO UPDATE
         SET requests = chat_request_limits.requests + 1
         WHERE chat_request_limits.requests < $4 RETURNING requests",
    )
    .bind(scope)
    .bind(token_hash(client_ip(headers)))
    .bind(minute)
    .bind(limit)
    .fetch_optional(db)
    .await;
    match count {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(message(
            StatusCode::TOO_MANY_REQUESTS,
            "잠시 후 다시 시도해 주세요.",
        )),
        Err(error) => {
            eprintln!("Chat request limit check failed: {error}");
            Err(message(
                StatusCode::SERVICE_UNAVAILABLE,
                "검색 서비스 상태를 확인할 수 없습니다.",
            ))
        }
    }
}

async fn chat_feedback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChatFeedback>,
) -> Response {
    if Uuid::parse_str(&input.visitor).is_err()
        || !(2..=300).contains(&input.message.trim().chars().count())
        || !input.url.starts_with("#/page/")
        || input.url.len() > 160
    {
        return message(
            StatusCode::BAD_REQUEST,
            "검색 결과 반응 정보가 올바르지 않습니다.",
        );
    }
    if let Err(response) = chat_request_limit(&state.db, &headers, "feedback", 60).await {
        return response;
    }
    let question_key = chat_question_key(&input.message);
    if input.liked {
        let issued = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM chat_search_receipts
             WHERE visitor = $1::text::uuid AND question_key = $2
               AND $3 = ANY(result_urls) AND expires_at > $4)",
        )
        .bind(&input.visitor)
        .bind(&question_key)
        .bind(&input.url)
        .bind(now_seconds())
        .fetch_one(&state.db)
        .await;
        match issued {
            Ok(true) => {}
            Ok(false) => {
                return message(
                    StatusCode::BAD_REQUEST,
                    "검색을 다시 실행한 뒤 반응을 남겨 주세요.",
                );
            }
            Err(error) => {
                eprintln!("Chat search receipt lookup failed: {error}");
                return message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "검색 결과를 확인할 수 없습니다.",
                );
            }
        }
    }
    let statement = if input.liked {
        "INSERT INTO chat_likes (question_key, result_url, visitor) VALUES ($1, $2, $3::text::uuid) ON CONFLICT DO NOTHING"
    } else {
        "DELETE FROM chat_likes WHERE question_key = $1 AND result_url = $2 AND visitor = $3::text::uuid"
    };
    match sqlx::query(statement)
        .bind(question_key)
        .bind(&input.url)
        .bind(&input.visitor)
        .execute(&state.db)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "반응을 저장하지 못했습니다.",
        ),
    }
}

async fn site_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChatRequest>,
) -> Response {
    if let Err(response) = chat_request_limit(&state.db, &headers, "search", 30).await {
        return response;
    }
    let query_text = input.message.trim();
    if query_text.chars().count() < 2 || query_text.chars().count() > 300 {
        return message(
            StatusCode::BAD_REQUEST,
            "질문은 2자 이상 300자 이하로 입력해 주세요.",
        );
    }
    let mut terms = normalized_search_terms(query_text);
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
    let time_sensitive = ["이번", "다음", "오늘", "내일", "최신", "식단", "급식"]
        .iter()
        .any(|term| query_text.contains(term));
    let question_key = chat_question_key(query_text);
    let pages = matching_content(
        &state.db,
        "site_pages",
        &terms,
        time_sensitive,
        &question_key,
    )
    .await;
    let articles = matching_content(
        &state.db,
        "site_articles",
        &terms,
        time_sensitive,
        &question_key,
    )
    .await;
    let (Ok(pages), Ok(articles)) = (pages, articles) else {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "학교 자료 검색에 실패했습니다.",
        );
    };
    let mut matches = Vec::new();
    for (payload, date, score, likes) in pages {
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
        matches.push(ChatMatch {
            title: title.to_owned(),
            excerpt,
            url: format!("#/page/{menu_no}"),
            kind: "page",
            score,
            likes,
            date,
        });
    }
    for (payload, date, score, likes) in articles {
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
        matches.push(ChatMatch {
            title: title.to_owned(),
            excerpt,
            url: format!("#/page/{menu_no}?menu_no={menu_no}&bno={bno}&board_mode=view"),
            kind: "article",
            score,
            likes,
            date,
        });
    }
    if contact_intent && !matches.iter().any(|item| item.url == "#/page/20") {
        if let Ok(Some(payload)) = sqlx::query_scalar::<_, serde_json::Value>(&format!(
            "SELECT payload FROM site_pages WHERE menu_no = '20' AND {PUBLIC_CONTENT}"
        ))
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
                likes: 0,
                date: None,
            });
        }
    }
    if let Some(topic) = chat_topic(query_text) {
        if let Err(error) = sqlx::query("INSERT INTO chat_topic_daily (topic, day, measured_searches, no_results) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (topic, day) DO UPDATE SET searches = chat_topic_daily.searches + 1, measured_searches = chat_topic_daily.measured_searches + 1, no_results = chat_topic_daily.no_results + EXCLUDED.no_results")
            .bind(topic).bind(i64::from(matches.is_empty())).execute(&state.db).await {
            eprintln!("Chat topic aggregation failed: {error}");
        }
    }
    let visitor = input.visitor.filter(|id| Uuid::parse_str(id).is_ok());
    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| {
                if time_sensitive {
                    right.date.cmp(&left.date)
                } else {
                    right.likes.cmp(&left.likes)
                }
            })
            .then_with(|| left.url.cmp(&right.url))
    });
    matches.truncate(8);
    let urls: Vec<_> = matches.iter().map(|item| item.url.as_str()).collect();
    let liked = sqlx::query_scalar::<_, String>(
        "SELECT result_url FROM chat_likes WHERE question_key = $1 AND result_url = ANY($2) AND visitor = $3::text::uuid"
    ).bind(&question_key).bind(&urls).bind(&visitor).fetch_all(&state.db).await.unwrap_or_default();
    if let Some(visitor) = visitor {
        let urls: Vec<_> = matches.iter().map(|item| item.url.as_str()).collect();
        if let Err(error) = sqlx::query(
            "INSERT INTO chat_search_receipts (visitor, question_key, result_urls, expires_at)
             VALUES ($1::text::uuid, $2, $3, $4)
             ON CONFLICT (visitor, question_key) DO UPDATE
             SET result_urls = EXCLUDED.result_urls, expires_at = EXCLUDED.expires_at",
        )
        .bind(visitor)
        .bind(chat_question_key(query_text))
        .bind(urls)
        .bind(now_seconds() + 3600)
        .execute(&state.db)
        .await
        {
            eprintln!("Chat search receipt write failed: {error}");
        }
    }
    Json(serde_json::json!({"matches": matches, "liked": liked})).into_response()
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

async fn check_admin_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !request.method().is_safe()
        && let Some(origin) = &state.frontend_origin
        && request.headers().get(header::ORIGIN) != Some(origin)
    {
        return message(
            StatusCode::FORBIDDEN,
            "관리 요청의 출처를 확인할 수 없습니다.",
        );
    }
    next.run(request).await
}

async fn reserve_login_attempt(db: &PgPool, ip: &str) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(ip)
        .execute(&mut *tx)
        .await?;
    let cutoff = now_seconds() - 600;
    let attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = $1 AND attempted_at > $2",
    )
    .bind(ip)
    .bind(cutoff)
    .fetch_one(&mut *tx)
    .await?;
    if attempts >= 5 {
        return Ok(false);
    }
    sqlx::query("INSERT INTO login_attempts (ip, attempted_at) VALUES ($1, $2)")
        .bind(ip)
        .bind(cutoff + 600)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

fn client_ip(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or("unknown")
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
    let ip = client_ip(&headers);
    let _ = sqlx::query("DELETE FROM login_attempts WHERE attempted_at <= $1")
        .bind(now_seconds() - 600)
        .execute(&state.db)
        .await;
    let Ok(permit) = state.password_workers.clone().try_acquire_owned() else {
        return message(StatusCode::SERVICE_UNAVAILABLE, "Login service is busy");
    };
    match reserve_login_attempt(&state.db, ip).await {
        Ok(true) => {}
        Ok(false) => {
            return message(
                StatusCode::TOO_MANY_REQUESTS,
                "로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.",
            );
        }
        Err(error) => {
            eprintln!("Login rate limit check failed: {error}");
            return message(
                StatusCode::SERVICE_UNAVAILABLE,
                "로그인 상태를 확인할 수 없습니다.",
            );
        }
    }
    let hash = hash.clone();
    let password = input.password;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&hash).ok().is_some_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await;
    let Ok(verified) = verified else {
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Password verification failed",
        );
    };
    if input.username != *username || !verified {
        return message(
            StatusCode::UNAUTHORIZED,
            "아이디 또는 비밀번호를 확인해 주세요.",
        );
    }
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

#[derive(Deserialize)]
struct NoticeListQuery {
    menu_id: Option<String>,
    category: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

async fn list_notices(
    State(state): State<AppState>,
    Query(query): Query<NoticeListQuery>,
) -> Response {
    let limit = query
        .per_page
        .or(query.page.map(|_| 50))
        .map(|size| size.clamp(1, 100));
    let offset = (query.page.unwrap_or(1).clamp(1, 100_000) - 1) * limit.unwrap_or(0);
    let values = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices
         WHERE payload->'published' = 'true'::jsonb AND (
             ($1::text IS NULL AND ($2::text IS NULL OR payload->>'category' = $2))
             OR ($1 IS NOT NULL AND (
                 payload->>'menu_id' = $1
                 OR (payload->>'menu_id' IS NULL AND payload->>'category' = $2)
             ))
         )
         ORDER BY created_at DESC, id LIMIT $3 OFFSET $4",
    )
    .bind(query.menu_id)
    .bind(query.category)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await;
    match values {
        Ok(values) => Json(
            values
                .into_iter()
                .filter_map(|value| serde_json::from_value::<Notice>(value).ok())
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

async fn notice_image(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match sqlx::query_as::<_, (bool, String, Vec<u8>)>(
        "SELECT (n.payload->'published' = 'true'::jsonb) IS TRUE, i.content_type, i.data
         FROM notice_images i JOIN notices n ON n.id = i.notice_id WHERE i.notice_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some((published, content_type, bytes))) => {
            if !published && session_user(&headers, &state).await.is_none() {
                return StatusCode::NOT_FOUND.into_response();
            }
            let mut response = Body::from(bytes).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            response.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
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

async fn notice_attachment(
    State(state): State<AppState>,
    Path((notice_id, attachment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let record = sqlx::query_as::<_, (serde_json::Value, String, String, Vec<u8>)>(
        "SELECT n.payload, a.filename, a.content_type, a.data FROM notices n JOIN notice_attachments a ON a.notice_id = n.id WHERE n.id = $1 AND a.id = $2",
    )
    .bind(notice_id)
    .bind(attachment_id)
    .fetch_optional(&state.db)
    .await;
    match record {
        Ok(Some((payload, filename, content_type, bytes))) => {
            let published = payload
                .get("published")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
            if !published && session_user(&headers, &state).await.is_none() {
                return StatusCode::NOT_FOUND.into_response();
            }
            let mut response = Body::from(bytes).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            let disposition = format!(
                "attachment; filename=attachment; filename*=UTF-8''{}",
                encode_header_filename(&filename)
            );
            if let Ok(value) = HeaderValue::from_str(&disposition) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, value);
            }
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            response.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            response
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Attachment could not be loaded.",
        ),
    }
}

async fn upload_notice_attachment(
    State(state): State<AppState>,
    Path(notice_id): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    let field = match multipart.next_field().await {
        Ok(Some(field)) if field.name() == Some("file") => field,
        _ => return message(StatusCode::BAD_REQUEST, "A file field is required."),
    };
    let Some(filename) = field.file_name().and_then(safe_attachment_filename) else {
        return message(StatusCode::BAD_REQUEST, "Attachment filename is invalid.");
    };
    let bytes = match field.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => return message(StatusCode::BAD_REQUEST, "Attachment could not be read."),
    };
    match multipart.next_field().await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return message(
                StatusCode::BAD_REQUEST,
                "Upload one attachment per request.",
            );
        }
        Err(_) => return message(StatusCode::BAD_REQUEST, "Attachment request is invalid."),
    }
    let content_type = match validate_attachment(&filename, &bytes) {
        Ok(content_type) => content_type,
        Err(error) => return message(StatusCode::BAD_REQUEST, error),
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attachment could not be saved.",
            );
        }
    };
    let payload = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices WHERE id = $1 FOR UPDATE",
    )
    .bind(&notice_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(payload)) => payload,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Notice could not be loaded.",
            );
        }
    };
    let mut notice = match serde_json::from_value::<Notice>(payload) {
        Ok(notice) => notice,
        Err(_) => return message(StatusCode::INTERNAL_SERVER_ERROR, "Notice data is invalid."),
    };
    if notice.attachments.len() >= 20 {
        return message(
            StatusCode::BAD_REQUEST,
            "A notice can have at most 20 attachments.",
        );
    }
    let attachment_id = Uuid::new_v4().to_string();
    let sort_order = notice.attachments.len() as i32;
    let attachment = NoticeAttachment {
        id: attachment_id.clone(),
        filename,
        content_type: content_type.to_owned(),
        size_bytes: bytes.len(),
        url: format!("/notices/{notice_id}/attachments/{attachment_id}"),
    };
    notice.attachments.push(attachment.clone());
    if sqlx::query("INSERT INTO notice_attachments (id, notice_id, filename, content_type, size_bytes, sort_order, data) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(&attachment.id)
        .bind(&notice_id)
        .bind(&attachment.filename)
        .bind(&attachment.content_type)
        .bind(attachment.size_bytes as i64)
        .bind(sort_order)
        .bind(bytes.as_ref())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "Attachment could not be saved.");
    }
    if sqlx::query("UPDATE notices SET payload = $2 WHERE id = $1")
        .bind(&notice_id)
        .bind(serde_json::to_value(&notice).unwrap_or_default())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Attachment metadata could not be saved.",
        );
    }
    if tx.commit().await.is_err() {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Attachment could not be saved.",
        );
    }
    (StatusCode::CREATED, Json(attachment)).into_response()
}

async fn delete_notice_attachment(
    State(state): State<AppState>,
    Path((notice_id, attachment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&headers, &state).await {
        return response;
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attachment could not be removed.",
            );
        }
    };
    let payload = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices WHERE id = $1 FOR UPDATE",
    )
    .bind(&notice_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(payload)) => payload,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Notice could not be loaded.",
            );
        }
    };
    let mut notice = match serde_json::from_value::<Notice>(payload) {
        Ok(notice) => notice,
        Err(_) => return message(StatusCode::INTERNAL_SERVER_ERROR, "Notice data is invalid."),
    };
    let before = notice.attachments.len();
    notice
        .attachments
        .retain(|attachment| attachment.id != attachment_id);
    if before == notice.attachments.len() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if sqlx::query("DELETE FROM notice_attachments WHERE id = $1 AND notice_id = $2")
        .bind(&attachment_id)
        .bind(&notice_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("UPDATE notices SET payload = $2 WHERE id = $1")
            .bind(&notice_id)
            .bind(serde_json::to_value(&notice).unwrap_or_default())
            .execute(&mut *tx)
            .await
            .is_err()
    {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Attachment could not be removed.",
        );
    }
    match tx.commit().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Attachment could not be removed.",
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
        attachments: Vec::new(),
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
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The request could not be saved.",
            );
        }
    };
    let old_value = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM notices WHERE id = $1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
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
        attachments: old.attachments,
        title: input.title.trim().into(),
        body: input.body.trim().into(),
        published: input.published,
        created_at: old.created_at,
        updated_at: now_seconds().to_string(),
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
    let started = std::time::Instant::now();
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let connected = started.elapsed();
    initialize_db(&db).await?;
    eprintln!(
        "Database startup: connect_ms={}, initialize_ms={}",
        connected.as_millis(),
        (started.elapsed() - connected).as_millis()
    );
    let same_site = env::var("COOKIE_SAME_SITE").unwrap_or_else(|_| "None".into());
    let secure_cookie =
        env::var("COOKIE_SECURE").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !["Strict", "Lax", "None"].contains(&same_site.as_str())
        || (same_site == "None" && !secure_cookie)
    {
        return Err("COOKIE_SAME_SITE=None requires COOKIE_SECURE=true; allowed values are Strict, Lax, and None".into());
    }
    let frontend_origin = env::var("FRONTEND_ORIGIN")
        .ok()
        .map(|value| value.parse::<HeaderValue>())
        .transpose()?;
    let username = env::var("ADMIN_USERNAME")
        .ok()
        .filter(|value| !value.is_empty());
    let password = env::var("ADMIN_PASSWORD")
        .ok()
        .filter(|value| value.chars().count() >= 12);
    if same_site == "None" && username.is_some() && password.is_some() && frontend_origin.is_none()
    {
        return Err("FRONTEND_ORIGIN is required for cross-site administrator cookies".into());
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
        username,
        password_hash: password.map(|password| {
            use argon2::PasswordHasher;
            use argon2::password_hash::SaltString;
            Argon2::default()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                .map(|h| h.to_string())
                .unwrap_or_default()
        }),
        secure_cookie,
        same_site,
        frontend_origin: frontend_origin.clone(),
        password_workers: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let admin = Router::new()
        .route("/api/admin/chat/stats", get(admin_chat_stats))
        .route("/api/admin/site-import", post(import_site))
        .route("/api/admin/login", post(login))
        .route("/api/admin/logout", post(logout))
        .route("/api/admin/session", get(admin_session))
        .route("/api/admin/notices", get(admin_notices).post(create_notice))
        .route(
            "/api/admin/notices/{id}",
            put(update_notice).delete(delete_notice),
        )
        .route(
            "/api/admin/notices/{id}/attachments",
            post(upload_notice_attachment),
        )
        .route(
            "/api/admin/notices/{id}/attachments/{attachment_id}",
            axum::routing::delete(delete_notice_attachment),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            check_admin_origin,
        ));
    let mut router = Router::new()
        .route("/api/health", get(health))
        .route("/api/ready", get(readiness))
        .route("/api/site/pages/{menu_no}", get(site_page))
        .route("/api/site/image", get(proxy_site_image))
        .route("/api/site/boards/{menu_no}", get(site_board))
        .route("/api/site/articles/{menu_no}/{bno}", get(site_article))
        .route("/api/site/chat", post(site_chat))
        .route("/api/site/chat/popular", get(popular_chat_topics))
        .route("/api/site/chat/feedback", post(chat_feedback))
        .route("/api/notices", get(list_notices))
        .route("/api/notices/{id}", get(get_notice))
        .route("/api/notices/{id}/image", get(notice_image))
        .route(
            "/api/notices/{id}/attachments/{attachment_id}",
            get(notice_attachment),
        )
        .merge(admin)
        .layer(RequestBodyLimitLayer::new(4 * 1024 * 1024))
        .with_state(state);
    if let Some(origin) = frontend_origin {
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
        MAX_ATTACHMENT_BYTES, NoticeInput, STANDARD, allowed_source_image_url, decode_notice_image,
        normalized_search_terms, safe_attachment_filename, validate_attachment, validate_notice,
    };
    use base64::Engine;

    // Run against an empty, disposable PostgreSQL database.
    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database and test configuration"]
    async fn postgres_http_regressions() {
        use super::*;
        use serde_json::json;
        use tower::ServiceExt;

        let db = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        assert!(
            sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('public.notices')::text")
                .fetch_one(&db)
                .await
                .unwrap()
                .is_none(),
            "use an empty, disposable test database"
        );

        let legacy = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(5).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        if env::var("DKIS_TEST_UPGRADE").as_deref() == Ok("1") {
            legacy.run(&db).await.unwrap();
            sqlx::query("INSERT INTO site_pages VALUES ('10', 'Legacy', $1)")
                .bind(json!({"menu_no":"10","title":"Legacy","body_html":"imported"}))
                .execute(&db)
                .await
                .unwrap();
        }
        let router = app().await.unwrap();
        let request = |method: &str,
                       path: &str,
                       origin: &str,
                       cookie: &str,
                       content_type: &str,
                       body: Body| {
            router.clone().oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::ORIGIN, origin)
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(body)
                    .unwrap(),
            )
        };
        let origin = env::var("FRONTEND_ORIGIN").unwrap();
        let json_type = "application/json";
        assert_eq!(
            request("GET", "/api/ready", &origin, "", json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            200
        );
        if env::var("DKIS_TEST_UPGRADE").as_deref() == Ok("1") {
            assert_eq!(
                request(
                    "GET",
                    "/api/site/pages/10",
                    &origin,
                    "",
                    json_type,
                    Body::empty()
                )
                .await
                .unwrap()
                .status(),
                200
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notices")
                .fetch_one(&db)
                .await
                .unwrap(),
            0
        );
        for page in [
            json!({"menu_no":"20","title":"연락처","body_html":"숨김","access_status":"restricted"}),
            json!({"menu_no":"21","title":"학교","body_html":"<a href='전화번호'>학교</a>"}),
        ] {
            sqlx::query("INSERT INTO site_pages VALUES ($1, $2, $3)")
                .bind(page["menu_no"].as_str())
                .bind(page["title"].as_str())
                .bind(&page)
                .execute(&db)
                .await
                .unwrap();
        }
        for (bno, date) in [("1", "2025.01.01"), ("2", "2026-01-01")] {
            sqlx::query("INSERT INTO site_articles VALUES ('47', $1, 0, $2)")
                .bind(bno)
                .bind(json!({"menu_no":"47","bno":bno,"title":"최신 공지","metadata_text":date}))
                .execute(&db)
                .await
                .unwrap();
        }
        assert_eq!(
            request(
                "GET",
                "/api/site/pages/20",
                &origin,
                "",
                json_type,
                Body::empty()
            )
            .await
            .unwrap()
            .status(),
            404
        );
        let visitor = Uuid::new_v4().to_string();
        for (question, count) in [("전화번호", 0), ("최신 공지", 2)] {
            let response = request(
                "POST",
                "/api/site/chat",
                &origin,
                "",
                json_type,
                Body::from(json!({"message": question, "visitor": visitor}).to_string()),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), 200);
            let bytes = axum::body::to_bytes(response.into_body(), 32768)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["matches"].as_array().unwrap().len(), count);
            if count > 0 {
                assert!(
                    json["matches"][0]["url"]
                        .as_str()
                        .unwrap()
                        .contains("bno=2")
                );
                for (url, expected) in [
                    (json["matches"][0]["url"].as_str().unwrap(), 204),
                    ("#/page/99", 400),
                ] {
                    assert_eq!(request("POST", "/api/site/chat/feedback", &origin, "", json_type,
                        Body::from(json!({"message":question,"visitor":visitor,"url":url,"liked":true}).to_string()))
                        .await.unwrap().status(), expected);
                }
            }
        }

        let headers = HeaderMap::new();
        assert!(chat_request_limit(&db, &headers, "test", 1).await.is_ok());
        assert_eq!(
            chat_request_limit(&db, &headers, "test", 1)
                .await
                .unwrap_err()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        let mut attempts = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let db = db.clone();
            attempts.spawn(async move { reserve_login_attempt(&db, "192.0.2.1").await.unwrap() });
        }
        let mut admitted = 0;
        while let Some(result) = attempts.join_next().await {
            admitted += usize::from(result.unwrap());
        }
        assert_eq!(admitted, 5);

        let login = json!({"username":env::var("ADMIN_USERNAME").unwrap(),"password":env::var("ADMIN_PASSWORD").unwrap()});
        assert_eq!(
            request(
                "POST",
                "/api/admin/login",
                "https://invalid.example",
                "",
                json_type,
                Body::from(login.to_string())
            )
            .await
            .unwrap()
            .status(),
            403
        );
        let response = request(
            "POST",
            "/api/admin/login",
            &origin,
            "",
            json_type,
            Body::from(login.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let draft = json!({"category":"공지사항","title":"Test","body":"Draft","published":false});
        let response = request(
            "POST",
            "/api/admin/notices",
            &origin,
            &cookie,
            json_type,
            Body::from(draft.to_string()),
        )
        .await
        .unwrap();
        assert!(response.status().is_success());
        let id: String = sqlx::query_scalar("SELECT id FROM notices")
            .fetch_one(&db)
            .await
            .unwrap();
        let multipart = b"--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.pdf\"\r\n\r\n%PDF-1.7\r\n--test--\r\n";
        let response = request(
            "POST",
            &format!("/api/admin/notices/{id}/attachments"),
            &origin,
            &cookie,
            "multipart/form-data; boundary=test",
            Body::from(multipart.as_slice()),
        )
        .await
        .unwrap();
        assert!(response.status().is_success());
        let attachment: String = sqlx::query_scalar("SELECT id FROM notice_attachments")
            .fetch_one(&db)
            .await
            .unwrap();
        let path = format!("/api/notices/{id}/attachments/{attachment}");
        assert_eq!(
            request("GET", &path, &origin, "", json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            request("GET", &path, &origin, &cookie, json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            200
        );
        let mut published = draft;
        published["published"] = json!(true);
        assert!(
            request(
                "PUT",
                &format!("/api/admin/notices/{id}"),
                &origin,
                &cookie,
                json_type,
                Body::from(published.to_string())
            )
            .await
            .unwrap()
            .status()
            .is_success()
        );
        assert_eq!(
            request("GET", &path, &origin, "", json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            200
        );
        assert!(
            request(
                "DELETE",
                &format!("/api/admin/notices/{id}/attachments/{attachment}"),
                &origin,
                &cookie,
                json_type,
                Body::empty()
            )
            .await
            .unwrap()
            .status()
            .is_success()
        );
        assert_eq!(
            request("GET", &path, &origin, "", json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            404
        );
    }

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

    #[test]
    fn search_terms_match_korean_queries_with_particles() {
        let terms = normalized_search_terms("급식은 어디에서 확인하나요?");
        assert!(terms.iter().any(|term| term == "급식은"));
        assert!(terms.iter().any(|term| term == "급식"));
        assert!(terms.iter().any(|term| term == "어디에서"));
        assert!(terms.iter().any(|term| term == "어디"));
        assert!(terms.len() <= 8);
    }

    #[test]
    fn attachments_require_allowed_extensions_and_matching_signatures() {
        assert_eq!(
            validate_attachment("안내.pdf", b"%PDF-1.7"),
            Ok("application/pdf")
        );
        assert_eq!(
            validate_attachment("안내.txt", "학교 안내".as_bytes()),
            Ok("text/plain; charset=utf-8")
        );
        assert!(validate_attachment("payload.exe", b"MZ").is_err());
        assert!(validate_attachment("fake.pdf", b"not a PDF").is_err());
        assert!(validate_attachment("large.txt", &vec![b'a'; MAX_ATTACHMENT_BYTES + 1]).is_err());
        assert_eq!(
            safe_attachment_filename("..\\안내.pdf").as_deref(),
            Some("안내.pdf")
        );
        assert!(safe_attachment_filename("bad\nname.pdf").is_none());
    }
}
