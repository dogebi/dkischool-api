-- 결과 없음 집계와 집계 대상 검색 횟수를 저장한다.
ALTER TABLE chat_topic_daily
    ADD COLUMN measured_searches BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN no_results BIGINT NOT NULL DEFAULT 0;
