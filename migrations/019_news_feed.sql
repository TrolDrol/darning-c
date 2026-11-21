CREATE TABLE bank_news_source (
    id text PRIMARY KEY,
    publisher text NOT NULL,
    byline text NOT NULL,
    title text NOT NULL,
    summary text NOT NULL,
    url text NOT NULL UNIQUE,
    published_at timestamptz NOT NULL,
    source_updated_at timestamptz NOT NULL
);
CREATE INDEX bank_news_source_recent_idx ON bank_news_source(source_updated_at DESC, id);

ALTER TABLE bank_news_post ALTER COLUMN author DROP NOT NULL;
ALTER TABLE bank_news_post ADD COLUMN source_id text REFERENCES bank_news_source(id);
ALTER TABLE bank_news_post ADD CHECK ((author IS NULL) = (source_id IS NOT NULL));
ALTER TABLE bank_news_post ADD UNIQUE (organization_id, source_id);
