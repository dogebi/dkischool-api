-- 학교 자료 검색용 제목과 본문을 정규화하고 인덱싱한다.
CREATE FUNCTION school_search_body(payload jsonb) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT regexp_replace(coalesce(payload->>'body_html', ''), '<[^>]+>', ' ', 'g') $$;

CREATE INDEX site_pages_search_text_idx ON site_pages USING gin (
    ((coalesce(payload->>'title', '') || ' ' || school_search_body(payload))) gin_trgm_ops
);
CREATE INDEX site_articles_search_text_idx ON site_articles USING gin (
    ((coalesce(payload->>'title', '') || ' ' || school_search_body(payload))) gin_trgm_ops
);

DROP INDEX site_pages_payload_trgm_idx;
DROP INDEX site_articles_payload_trgm_idx;
