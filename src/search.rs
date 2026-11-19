// 학교 자료 검색 순위, 검색 반응과 관리자 통계를 처리합니다.
use super::{
    AppState,
    auth::{client_ip, token_hash},
    message, now_seconds,
    school::PUBLIC_CONTENT,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::collections::HashMap;
use uuid::Uuid;

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

pub(super) fn normalized_search_terms(query: &str) -> Vec<String> {
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

pub(super) fn chat_question_key(question: &str) -> String {
    let normalized = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    token_hash(&normalized)
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
    Query(query): Query<HashMap<String, String>>,
) -> Response {
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

pub(super) async fn chat_request_limit(
    db: &PgPool,
    headers: &HeaderMap,
    scope: &str,
    limit: i32,
) -> Result<(), Box<Response>> {
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
        Ok(None) => Err(Box::new(message(
            StatusCode::TOO_MANY_REQUESTS,
            "잠시 후 다시 시도해 주세요.",
        ))),
        Err(error) => {
            eprintln!("Chat request limit check failed: {error}");
            Err(Box::new(message(
                StatusCode::SERVICE_UNAVAILABLE,
                "검색 서비스 상태를 확인할 수 없습니다.",
            )))
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
        return *response;
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
        return *response;
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
    if contact_intent
        && !matches.iter().any(|item| item.url == "#/page/20")
        && let Ok(Some(payload)) = sqlx::query_scalar::<_, serde_json::Value>(&format!(
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
    if let Some(topic) = chat_topic(query_text)
        && let Err(error) = sqlx::query("INSERT INTO chat_topic_daily (topic, day, measured_searches, no_results) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (topic, day) DO UPDATE SET searches = chat_topic_daily.searches + 1, measured_searches = chat_topic_daily.measured_searches + 1, no_results = chat_topic_daily.no_results + EXCLUDED.no_results")
            .bind(topic).bind(i64::from(matches.is_empty())).execute(&state.db).await {
            eprintln!("Chat topic aggregation failed: {error}");
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

pub(super) fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/site/chat", post(site_chat))
        .route("/api/site/chat/popular", get(popular_chat_topics))
        .route("/api/site/chat/feedback", post(chat_feedback))
}

pub(super) fn admin_routes() -> Router<AppState> {
    Router::new().route("/api/admin/chat/stats", get(admin_chat_stats))
}
