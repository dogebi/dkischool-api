-- ?? ?? ?? ??? ???? ?? ??? ????? ????.
CREATE TABLE chat_request_limits (
    scope text NOT NULL,
    client_key text NOT NULL,
    minute bigint NOT NULL,
    requests integer NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, client_key, minute)
);
CREATE INDEX chat_request_limits_expiry_idx ON chat_request_limits (minute);

CREATE TABLE chat_search_receipts (
    visitor uuid NOT NULL,
    question_key text NOT NULL,
    result_urls text[] NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (visitor, question_key)
);
CREATE INDEX chat_search_receipts_expiry_idx ON chat_search_receipts (expires_at);
