-- 페이지와 게시물 본문의 부분 문자열 검색을 위한 삼중문자 인덱스
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS site_pages_payload_trgm_idx
    ON site_pages USING GIN ((payload::text) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS site_articles_payload_trgm_idx
    ON site_articles USING GIN ((payload::text) gin_trgm_ops);
