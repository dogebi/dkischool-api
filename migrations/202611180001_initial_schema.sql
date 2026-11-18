-- 학교 페이지, 게시물, 관리자 세션 및 이미지 저장소의 초기 스키마
CREATE TABLE IF NOT EXISTS notices (
    id TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS notice_images (
    notice_id TEXT PRIMARY KEY REFERENCES notices(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    data BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    ip TEXT NOT NULL,
    attempted_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS site_pages (
    menu_no TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS site_articles (
    menu_no TEXT NOT NULL,
    bno TEXT NOT NULL,
    sort_order BIGINT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (menu_no, bno)
);

CREATE INDEX IF NOT EXISTS site_articles_order_idx
    ON site_articles (menu_no, sort_order);
