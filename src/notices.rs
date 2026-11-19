// 학교 공지, 대표 이미지와 첨부파일의 공개 및 관리 요청을 처리합니다.
use super::{AppState, auth::session_user, message, now_seconds};
use axum::{
    Json, Router,
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) const MAX_ATTACHMENT_BYTES: usize = 3 * 1024 * 1024;
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
pub(super) struct NoticeInput {
    pub(super) category: String,
    #[serde(default)]
    pub(super) menu_id: Option<String>,
    #[serde(default)]
    pub(super) image_data: Option<String>,
    #[serde(default)]
    pub(super) remove_image: bool,
    pub(super) title: String,
    pub(super) body: String,
    pub(super) published: bool,
}

pub(super) fn validate_notice(input: &NoticeInput) -> Result<(), String> {
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

pub(super) fn decode_notice_image(value: &str) -> Result<(String, Vec<u8>), String> {
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

pub(super) fn validate_attachment(filename: &str, bytes: &[u8]) -> Result<&'static str, String> {
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

pub(super) fn safe_attachment_filename(value: &str) -> Option<String> {
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
    mut multipart: Multipart,
) -> Response {
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
) -> Response {
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

async fn admin_notices(State(state): State<AppState>) -> Response {
    match read_notices(&state.db).await {
        Ok(notices) => Json(notices).into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "게시물을 불러오지 못했습니다.",
        ),
    }
}

async fn create_notice(State(state): State<AppState>, Json(input): Json<NoticeInput>) -> Response {
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
    if let Some((content_type, bytes)) = image
        && sqlx::query(
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
    Path(id): Path<String>,
    Json(input): Json<NoticeInput>,
) -> Response {
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
    } else if input.remove_image
        && sqlx::query("DELETE FROM notice_images WHERE notice_id = $1")
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
    if tx.commit().await.is_err() {
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be saved.",
        );
    }
    Json(notice).into_response()
}

async fn delete_notice(State(state): State<AppState>, Path(id): Path<String>) -> Response {
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

pub(super) fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/notices", get(list_notices))
        .route("/api/notices/{id}", get(get_notice))
        .route("/api/notices/{id}/image", get(notice_image))
        .route(
            "/api/notices/{id}/attachments/{attachment_id}",
            get(notice_attachment),
        )
}

pub(super) fn admin_routes() -> Router<AppState> {
    Router::new()
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
            delete(delete_notice_attachment),
        )
}
