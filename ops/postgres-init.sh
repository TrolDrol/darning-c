#!/usr/bin/env bash

(
    set -euo pipefail
    BANK_ROLE_PASSWORD="$(cat /run/darning/db/password)"
    test -n "$BANK_ROLE_PASSWORD"
    export BANK_ROLE_PASSWORD

    psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv bank_password BANK_ROLE_PASSWORD
CREATE ROLE bank LOGIN PASSWORD :'bank_password';
ALTER DATABASE bank OWNER TO bank;
REVOKE CONNECT ON DATABASE bank FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
)
