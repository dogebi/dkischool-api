-- 교직원 게시물의 여러 파일 첨부 저장소
CREATE TABLE IF NOT EXISTS notice_attachments (
    id TEXT PRIMARY KEY,
    notice_id TEXT NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sort_order INTEGER NOT NULL,
    data BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS notice_attachments_notice_order_idx
    ON notice_attachments (notice_id, sort_order);
