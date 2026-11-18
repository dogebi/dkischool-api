-- 채팅 질문 주제의 일별 검색 횟수와 검색 결과별 반응을 저장한다.
CREATE TABLE chat_topic_daily (
    topic TEXT NOT NULL,
    day DATE NOT NULL,
    searches BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (topic, day)
);

CREATE TABLE chat_likes (
    question_key TEXT NOT NULL,
    result_url TEXT NOT NULL,
    visitor UUID NOT NULL,
    PRIMARY KEY (question_key, result_url, visitor)
);
