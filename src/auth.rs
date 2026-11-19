// 관리자 로그인, 세션과 요청 출처를 검증합니다.
use super::{AppState, Message, message, now_seconds};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const SESSION_COOKIE: &str = "dkis_admin";
const SESSION_SECONDS: i64 = 8 * 60 * 60;
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
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

pub(super) fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub(super) async fn session_user(headers: &HeaderMap, state: &AppState) -> Option<String> {
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

#[derive(Clone)]
struct AdminUser(String);

pub(super) async fn require_admin(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if state.username.is_none() || state.password_hash.is_none() {
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            "서버에 관리자 계정이 설정되지 않았습니다.",
        );
    }
    let Some(username) = session_user(request.headers(), &state).await else {
        return message(StatusCode::UNAUTHORIZED, "관리자 로그인이 필요합니다.");
    };
    request.extensions_mut().insert(AdminUser(username));
    next.run(request).await
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

pub(super) async fn check_admin_origin(
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

pub(super) async fn reserve_login_attempt(db: &PgPool, ip: &str) -> Result<bool, sqlx::Error> {
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

pub(super) fn client_ip(headers: &HeaderMap) -> &str {
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

async fn admin_session(Extension(AdminUser(username)): Extension<AdminUser>) -> Response {
    Json(serde_json::json!({"authenticated":true,"username":username})).into_response()
}

pub(super) fn protected_routes() -> Router<AppState> {
    Router::new().route("/api/admin/session", get(admin_session))
}

pub(super) fn session_routes() -> Router<AppState> {
    Router::new()
        .route("/api/admin/login", post(login))
        .route("/api/admin/logout", post(logout))
}
