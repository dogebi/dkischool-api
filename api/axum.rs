// GitHub Pages 학교 홈페이지용 Axum 관리자 API 서버리스 진입점
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/notices.rs"]
mod notices;
#[path = "../src/school.rs"]
mod school;
#[path = "../src/search.rs"]
mod search;

use argon2::Argon2;
use auth::{check_admin_origin, require_admin};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use rand_core::OsRng;
use school::allowed_source_image_url;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use vercel_runtime::{Error, axum::VercelLayer};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

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

async fn initialize_db(db: &PgPool) -> Result<(), Error> {
    MIGRATOR.run(db).await?;
    if let Some(migration) = MIGRATOR.iter().last() {
        eprintln!("Database migrations applied through {}", migration.version);
    }
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
    let admin = auth::protected_routes()
        .merge(notices::admin_routes())
        .merge(school::admin_routes())
        .merge(search::admin_routes())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin))
        .merge(auth::session_routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            check_admin_origin,
        ));
    let mut router = Router::new()
        .route("/api/health", get(health))
        .route("/api/ready", get(readiness))
        .merge(notices::public_routes())
        .merge(school::public_routes())
        .merge(search::public_routes())
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
#[path = "../src/tests.rs"]
mod tests;
