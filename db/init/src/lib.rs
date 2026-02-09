use anyhow::{anyhow, Context, Result};
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
    sqlite::{Connection, Value},
};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_SQL_FILES: &[&str] = &["sql/schema.sql"];
const MARKER_TABLE: &str = "kc_schema_version";
const DEFAULT_VERSION: &str = "1";

#[http_component]
fn handle_db_init(req: Request) -> Result<Response> {
    if req.method().as_str() != "POST" {
        return plain_response(405, "method not allowed");
    }

    let conn = Connection::open_default().context("open default sqlite database")?;
    if is_initialized(&conn)? {
        return plain_response(200, "already initialized");
    }

    conn.execute("BEGIN", &[])
        .context("begin initialization transaction")?;
    let init_result = (|| {
        let sql_files = resolve_sql_files();
        for path in sql_files {
            let sql = read_sql_file(&path)?;
            apply_sql(&conn, &sql).with_context(|| format!("apply sql file: {path}"))?;
        }

        if let Ok(inline_sql) = config::get("db_init_sql") {
            if !inline_sql.trim().is_empty() {
                apply_sql(&conn, &inline_sql).context("apply inline sql")?;
            }
        }

        mark_initialized(&conn)?;
        Ok(())
    })();

    if let Err(err) = init_result {
        let _ = conn.execute("ROLLBACK", &[]);
        return Err(err);
    }

    conn.execute("COMMIT", &[])
        .context("commit initialization transaction")?;

    plain_response(200, "initialized")
}

fn resolve_sql_files() -> Vec<String> {
    match config::get("db_init_sql_files") {
        Ok(value) => value
            .split(',')
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .map(String::from)
            .collect(),
        Err(_) => DEFAULT_SQL_FILES.iter().map(|path| path.to_string()).collect(),
    }
}

fn read_sql_file(path: &str) -> Result<String> {
    let resolved = resolve_path(path)?;
    fs::read_to_string(&resolved)
        .with_context(|| format!("read sql file: {}", resolved.display()))
}

fn resolve_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let cwd = std::env::current_dir().context("get current working directory")?;
    Ok(cwd.join(path))
}

fn apply_sql(conn: &Connection, sql: &str) -> Result<()> {
    for statement in sql.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        conn.execute(trimmed, &[])
            .with_context(|| format!("execute statement: {trimmed}"))?;
    }
    Ok(())
}

fn is_initialized(conn: &Connection) -> Result<bool> {
    let rows = conn
        .query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
            &[Value::Text(MARKER_TABLE.to_string())],
        )
        .context("check marker table")?;

    for row in rows.rows() {
        let _: String = row.get("name").context("read marker table name")?;
        return Ok(true);
    }

    Ok(false)
}

fn mark_initialized(conn: &Connection) -> Result<()> {
    let version = config::get("db_init_version").unwrap_or_else(|_| DEFAULT_VERSION.to_string());

    conn.execute(
        "CREATE TABLE IF NOT EXISTS kc_schema_version (id INTEGER PRIMARY KEY, version TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))",
        &[],
    )
    .context("create marker table")?;

    conn.execute(
        "INSERT INTO kc_schema_version (id, version) SELECT 1, ?1 WHERE NOT EXISTS (SELECT 1 FROM kc_schema_version WHERE id=1)",
        &[Value::Text(version)],
    )
    .context("store schema version")?;

    Ok(())
}

fn plain_response(status: u16, body: &str) -> Result<Response> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body.as_bytes().to_vec())
        .map_err(|err| anyhow!("build response: {err}"))
}
