CREATE TABLE bank_news_post (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES bank_organization(id),
    author text NOT NULL REFERENCES bank_account(username),
    kind text NOT NULL CHECK (kind IN ('news', 'article')),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    body text NOT NULL CHECK (char_length(body) <= 5000),
    url text CHECK (char_length(url) BETWEEN 1 AND 2048),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz,
    hidden_at timestamptz,
    hidden_by text REFERENCES bank_account(username),
    UNIQUE (organization_id, id),
    CHECK (body <> '' OR (kind = 'article' AND url IS NOT NULL)),
    CHECK ((hidden_at IS NULL) = (hidden_by IS NULL))
);

CREATE INDEX bank_news_post_feed_idx ON bank_news_post (organization_id, created_at DESC, id DESC)
    WHERE hidden_at IS NULL;

CREATE TABLE bank_news_comment (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    post_id text NOT NULL,
    author text NOT NULL REFERENCES bank_account(username),
    body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz,
    hidden_at timestamptz,
    hidden_by text REFERENCES bank_account(username),
    FOREIGN KEY (organization_id, post_id) REFERENCES bank_news_post (organization_id, id),
    CHECK ((hidden_at IS NULL) = (hidden_by IS NULL))
);

CREATE INDEX bank_news_comment_thread_idx ON bank_news_comment (organization_id, post_id, created_at DESC, id DESC)
    WHERE hidden_at IS NULL;
