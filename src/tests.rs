// 백엔드 단위 테스트와 PostgreSQL HTTP 회귀 테스트를 실행합니다.
use super::{
    auth::reserve_login_attempt,
    notices::{
        MAX_ATTACHMENT_BYTES, NoticeInput, decode_notice_image, safe_attachment_filename,
        validate_attachment, validate_notice,
    },
    school::allowed_source_image_url,
    search::{chat_question_key, chat_request_limit, normalized_search_terms},
};
use axum::{body::Body, extract::Request, http::HeaderMap};
use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;

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
    let request =
        |method: &str, path: &str, origin: &str, cookie: &str, content_type: &str, body: Body| {
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
                assert_eq!(
                    request(
                        "POST",
                        "/api/site/chat/feedback",
                        &origin,
                        "",
                        json_type,
                        Body::from(
                            json!({"message":question,"visitor":visitor,"url":url,"liked":true})
                                .to_string()
                        )
                    )
                    .await
                    .unwrap()
                    .status(),
                    expected
                );
            }
        }
    }

    let winning_url = "#/page/99";
    for id in 90..=99 {
        let id = id.to_string();
        sqlx::query("INSERT INTO site_pages VALUES ($1, 'Handbook', $2)")
            .bind(&id)
            .bind(json!({"menu_no":id,"title":"Handbook"}))
            .execute(&db)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO chat_likes VALUES ($1, $2, $3::text::uuid)")
        .bind(chat_question_key("Handbook"))
        .bind(winning_url)
        .bind(&visitor)
        .execute(&db)
        .await
        .unwrap();
    let response = request(
        "POST",
        "/api/site/chat",
        &origin,
        "",
        json_type,
        Body::from(json!({"message":"Handbook","visitor":visitor}).to_string()),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 32768)
        .await
        .unwrap();
    let results: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(results["matches"][0]["url"], winning_url);
    assert_eq!(results["liked"], json!([winning_url]));

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

    for (method, path) in [
        ("GET", "/api/admin/chat/stats"),
        ("GET", "/api/admin/session"),
        ("GET", "/api/admin/notices"),
        ("POST", "/api/admin/notices"),
        ("PUT", "/api/admin/notices/test"),
        ("DELETE", "/api/admin/notices/test"),
        ("POST", "/api/admin/notices/test/attachments"),
        ("DELETE", "/api/admin/notices/test/attachments/file"),
        ("POST", "/api/admin/site-import"),
    ] {
        let response = request(method, path, &origin, "", json_type, Body::empty())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
    assert_eq!(
        request(
            "POST",
            "/api/admin/logout",
            &origin,
            "",
            json_type,
            Body::empty()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );

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
    let upload_path = format!("/api/admin/notices/{id}/attachments");
    let upload = || {
        request(
            "POST",
            &upload_path,
            &origin,
            &cookie,
            "multipart/form-data; boundary=test",
            Body::from(multipart.as_slice()),
        )
    };
    let (first, second) = tokio::join!(upload(), upload());
    assert!(first.unwrap().status().is_success());
    assert!(second.unwrap().status().is_success());
    let attachments: Vec<String> =
        sqlx::query_scalar("SELECT id FROM notice_attachments ORDER BY sort_order")
            .fetch_all(&db)
            .await
            .unwrap();
    let payload: serde_json::Value = sqlx::query_scalar("SELECT payload FROM notices")
        .fetch_one(&db)
        .await
        .unwrap();
    let listed: Vec<_> = payload["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attachment| attachment["id"].as_str().unwrap())
        .collect();
    assert_eq!(listed, attachments);
    assert_eq!(attachments.len(), 2);
    let attachment = &attachments[0];
    sqlx::query("INSERT INTO notice_images VALUES ($1, 'image/png', $2)")
        .bind(&id)
        .bind(b"test".as_slice())
        .execute(&db)
        .await
        .unwrap();
    let image_path = format!("/api/notices/{id}/image");
    assert_eq!(
        request("GET", &image_path, &origin, "", json_type, Body::empty())
            .await
            .unwrap()
            .status(),
        404
    );
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
    let mut published = draft.clone();
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
    for file_path in [&path, &image_path] {
        let response = request("GET", file_path, &origin, "", json_type, Body::empty())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
    }
    for (page, count) in [(1, 1), (2, 0)] {
        let listing = format!("/api/notices?page={page}&per_page=1");
        let response = request("GET", &listing, &origin, "", json_type, Body::empty())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), 32768)
            .await
            .unwrap();
        let notices: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(notices.len(), count);
    }
    assert!(
        request(
            "PUT",
            &format!("/api/admin/notices/{id}"),
            &origin,
            &cookie,
            json_type,
            Body::from(draft.to_string())
        )
        .await
        .unwrap()
        .status()
        .is_success()
    );
    for file_path in [&path, &image_path] {
        assert_eq!(
            request("GET", file_path, &origin, "", json_type, Body::empty())
                .await
                .unwrap()
                .status(),
            404
        );
    }
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
