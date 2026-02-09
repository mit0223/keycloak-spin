# db-init

SQLite initializer component for Spin.

## Build

```sh
cargo build --target wasm32-wasip2 --release
```

## Run (standalone)

```sh
spin up
```

## Configuration

- db_init_sql_files: Comma-separated SQL file paths. Defaults to sql/schema.sql.
- db_init_sql: Inline SQL applied after files.
- db_init_version: Schema version stored in kc_schema_version.
