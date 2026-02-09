use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use spin_sdk::{
    http::{Method, Request, Response},
    http_component,
    sqlite::{Connection, Value as SqlValue},
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
struct StubResponse<'a> {
    message: &'a str,
    method: &'a str,
    path: &'a str,
    query: &'a str,
    db_ready: bool,
    schema_version: Option<String>,
}

#[http_component]
fn handle_api(req: Request) -> Result<Response> {
    let method = req.method();
    let path = req.path();
    let query = req.query();

    let conn = Connection::open_default().context("open default sqlite database")?;
    ensure_schema(&conn)?;
    let schema_version = load_schema_version(&conn)?;

    if path == "/admin/realms" {
        return handle_realms(&conn, method, query, req.body());
    }

    if let Some((realm, rest)) = split_realm_path(path) {
        if rest.is_empty() {
            return handle_realm(&conn, method, realm, req.body());
        }
        match rest {
            "events" => return handle_realm_events(&conn, method, realm, query),
            "events/config" => return handle_events_config(&conn, method, realm, req.body()),
            "admin-events" => return handle_admin_events(&conn, method, realm, query),
            "keys" => return handle_keys(&conn, method, realm),
            "localization" => return handle_localizations(&conn, method, realm),
            _ => {}
        }
        if let Some(user_id) = rest.strip_prefix("attack-detection/brute-force/users/") {
            if !user_id.is_empty() && !user_id.contains('/') {
                return handle_brute_force_user(&conn, method, realm, user_id);
            }
        }
        if rest == "attack-detection/brute-force/users" {
            return handle_brute_force_all(&conn, method, realm);
        }
        if rest == "clients" {
            return handle_clients(&conn, method, realm, query, req.body());
        }
        if rest == "components" {
            return handle_components(&conn, method, realm, query, req.body());
        }
        if rest == "identity-provider/instances" {
            return handle_identity_provider_instances(&conn, method, realm, query, req.body());
        }
        if rest == "clients-initial-access" {
            return handle_clients_initial_access(&conn, method, realm, req.body());
        }
        if let Some(token_id) = rest.strip_prefix("clients-initial-access/") {
            if !token_id.is_empty() && !token_id.contains('/') {
                return handle_client_initial_access(&conn, method, realm, token_id);
            }
        }
        match rest {
            "client-description-converter" => {
                return handle_client_description_converter(&conn, method, realm, req.body())
            }
            "credential-registrators" => {
                return handle_credential_registrators(&conn, method, realm)
            }
            "identity-provider/import-config" => {
                return handle_identity_provider_import_config(&conn, method, realm, req.body())
            }
            "groups" => return handle_groups(&conn, method, realm, query, req.body()),
            "groups/count" => return handle_groups_count(&conn, method, realm, query),
            "client-policies/policies" => {
                return handle_client_policies(&conn, method, realm, req.body())
            }
            "client-policies/profiles" => {
                return handle_client_profiles(&conn, method, realm, req.body())
            }
            "client-registration-policy/providers" => {
                return handle_client_registration_providers(&conn, method, realm)
            }
            "client-session-stats" => return handle_client_session_stats(&conn, method, realm),
            "client-types" => return handle_client_types(&conn, method, realm, req.body()),
            "identity-provider/upload-certificate" => {
                return handle_identity_provider_upload_certificate(&conn, method, realm, req.body())
            }
            _ => {}
        }
        if let Some(client_id) = rest.strip_prefix("clients/") {
            if !client_id.is_empty() && !client_id.contains('/') {
                return handle_client(&conn, method, realm, client_id, req.body());
            }
        }
        if let Some(tail) = rest.strip_prefix("group-by-path/") {
            if !tail.is_empty() {
                return handle_group_by_path(&conn, method, realm, tail);
            }
        }
        if let Some(tail) = rest.strip_prefix("groups/") {
            if let Some(response) =
                handle_group_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if rest == "roles" {
            return handle_roles(&conn, method, realm, query, req.body());
        }
        if let Some(tail) = rest.strip_prefix("roles/") {
            if let Some(response) =
                handle_role_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if let Some(tail) = rest.strip_prefix("roles-by-id/") {
            if let Some(response) =
                handle_role_by_id_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if rest == "users" {
            return handle_users(&conn, method, realm, query, req.body());
        }
        if rest == "users/count" {
            return handle_users_count(&conn, method, realm, query);
        }
        if rest == "users/profile" {
            return handle_users_profile(&conn, method, realm, req.body());
        }
        if rest == "users/profile/metadata" {
            return handle_users_profile_metadata(&conn, method, realm);
        }
        if rest == "users-management-permissions" {
            return handle_users_management_permissions(&conn, method, realm, req.body());
        }
        if rest == "workflows" {
            return handle_workflows(&conn, method, realm);
        }
        if let Some(workflow_id) = rest.strip_prefix("workflows/") {
            if let Some(resource_id) = workflow_id.strip_prefix("scheduled/") {
                if !resource_id.is_empty() && !resource_id.contains('/') {
                    return handle_workflows_scheduled(&conn, method, realm, resource_id);
                }
            }
            if !workflow_id.is_empty() && !workflow_id.contains('/') {
                return handle_workflow(&conn, method, realm, workflow_id);
            }
        }
        if let Some(tail) = rest.strip_prefix("users/") {
            if let Some(response) = handle_user_paths(&conn, method, realm, tail, req.body())? {
                return Ok(response);
            }
        }
        if let Some(session_id) = rest.strip_prefix("sessions/") {
            if !session_id.is_empty() && !session_id.contains('/') {
                return handle_realm_session(&conn, method, realm, session_id, query);
            }
        }
        if let Some(tail) = rest.strip_prefix("localization/") {
            if let Some(response) = handle_localization_paths(&conn, method, realm, tail, req.body())?
            {
                return Ok(response);
            }
        }
        if rest == "organizations" {
            return handle_organizations(&conn, method, realm, query, req.body());
        }
        if rest == "organizations/count" {
            return handle_organizations_count(&conn, method, realm, query);
        }
        if let Some(member_id) = rest.strip_prefix("organizations/members/") {
            if let Some(tail) = member_id.strip_suffix("/organizations") {
                if !tail.is_empty() && !tail.contains('/') {
                    return handle_organizations_for_member(&conn, method, realm, tail, query);
                }
            }
        }
        if let Some(tail) = rest.strip_prefix("organizations/") {
            if let Some(response) =
                handle_organization_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if let Some(tail) = rest.strip_prefix("identity-provider/instances/") {
            if let Some(response) =
                handle_identity_provider_instance_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if let Some(provider_id) = rest.strip_prefix("identity-provider/providers/") {
            if !provider_id.is_empty() && !provider_id.contains('/') {
                return handle_identity_provider_provider(&conn, method, realm, provider_id);
            }
        }
        if let Some(tail) = rest.strip_prefix("components/") {
            if let Some(response) =
                handle_component_paths(&conn, method, realm, tail, query, req.body())?
            {
                return Ok(response);
            }
        }
        if rest == "client-scopes" {
            return handle_client_scopes(&conn, method, realm, req.body());
        }
        if rest == "client-templates" {
            return handle_client_templates(&conn, method, realm, req.body());
        }
        if let Some(tail) = rest.strip_prefix("client-scopes/") {
            if let Some(response) = handle_client_scope_paths(&conn, method, realm, tail, req.body())?
            {
                return Ok(response);
            }
        }
        if let Some(tail) = rest.strip_prefix("client-templates/") {
            if let Some(response) = handle_client_scope_paths(&conn, method, realm, tail, req.body())?
            {
                return Ok(response);
            }
        }
        match rest {
            "authentication/authenticator-providers"
            | "authentication/client-authenticator-providers"
            | "authentication/form-action-providers"
            | "authentication/form-providers" => {
                return handle_auth_providers(&conn, method, realm)
            }
            "authentication/unregistered-required-actions" => {
                return handle_unregistered_required_actions(&conn, method, realm)
            }
            "authentication/register-required-action" => {
                return handle_register_required_action(&conn, method, realm, req.body())
            }
            "authentication/required-actions" => {
                return handle_required_actions(&conn, method, realm)
            }
            "authentication/executions" => {
                return handle_auth_executions(&conn, method, realm, req.body())
            }
            _ => {}
        }
        if let Some(tail) = rest.strip_prefix("authentication/required-actions/") {
            if let Some(alias) = tail.strip_suffix("/config") {
                if !alias.is_empty() && !alias.contains('/') {
                    return handle_required_action_config(&conn, method, realm, alias, req.body());
                }
            }
            if let Some(alias) = tail.strip_suffix("/config-description") {
                if !alias.is_empty() && !alias.contains('/') {
                    return handle_required_action_config_description(&conn, method, realm, alias);
                }
            }
            if let Some(alias) = tail.strip_suffix("/lower-priority") {
                if !alias.is_empty() && !alias.contains('/') {
                    return handle_required_action_priority(
                        &conn,
                        method,
                        realm,
                        alias,
                        -1,
                    );
                }
            }
            if let Some(alias) = tail.strip_suffix("/raise-priority") {
                if !alias.is_empty() && !alias.contains('/') {
                    return handle_required_action_priority(
                        &conn,
                        method,
                        realm,
                        alias,
                        1,
                    );
                }
            }
            if !tail.is_empty() && !tail.contains('/') {
                return handle_required_action(&conn, method, realm, tail, req.body());
            }
        }
        if let Some(tail) = rest.strip_prefix("authentication/executions/") {
            if let Some(exec_id) = tail.strip_suffix("/config") {
                if !exec_id.is_empty() && !exec_id.contains('/') {
                    return handle_auth_execution_config(
                        &conn,
                        method,
                        realm,
                        exec_id,
                        None,
                        req.body(),
                    );
                }
            }
            if let Some(exec_id) = tail.strip_suffix("/lower-priority") {
                if !exec_id.is_empty() && !exec_id.contains('/') {
                    return handle_auth_execution_priority(&conn, method, realm, exec_id, -1);
                }
            }
            if let Some(exec_id) = tail.strip_suffix("/raise-priority") {
                if !exec_id.is_empty() && !exec_id.contains('/') {
                    return handle_auth_execution_priority(&conn, method, realm, exec_id, 1);
                }
            }
            if let Some((exec_id, config_id)) = tail.split_once("/config/") {
                if !exec_id.is_empty()
                    && !exec_id.contains('/')
                    && !config_id.is_empty()
                    && !config_id.contains('/')
                {
                    return handle_auth_execution_config(
                        &conn,
                        method,
                        realm,
                        exec_id,
                        Some(config_id),
                        req.body(),
                    );
                }
            }
            if !tail.is_empty() && !tail.contains('/') {
                return handle_auth_execution(&conn, method, realm, tail, req.body());
            }
        }
        if rest == "authentication/flows" {
            return handle_auth_flows(&conn, method, realm, req.body());
        }
        if let Some(tail) = rest.strip_prefix("authentication/flows/") {
            if let Some(flow_alias) = tail.strip_suffix("/executions") {
                if !flow_alias.is_empty() && !flow_alias.contains('/') {
                    return handle_auth_flow_executions(
                        &conn,
                        method,
                        realm,
                        flow_alias,
                        req.body(),
                    );
                }
            } else if !tail.is_empty() && !tail.contains('/') {
                return handle_auth_flow_by_id(&conn, method, realm, tail, req.body());
            }
        }
    }

    let response = StubResponse {
        message: "not implemented",
        method: method_to_str(method),
        path,
        query,
        db_ready: schema_version.is_some(),
        schema_version,
    };

    let body = serde_json::to_vec(&response).context("serialize response")?;
    let mut builder = Response::builder();
    Ok(builder
        .status(501)
        .header("content-type", "application/json; charset=utf-8")
        .body(body)
        .build())
}

fn handle_realms(conn: &Connection, method: &Method, query: &str, body: &[u8]) -> Result<Response> {
    match method {
        Method::Get => list_realms(conn, query),
        Method::Post => create_realm(conn, body),
        _ => method_not_allowed(),
    }
}

fn handle_realm(conn: &Connection, method: &Method, realm: &str, body: &[u8]) -> Result<Response> {
    match method {
        Method::Get => get_realm(conn, realm),
        Method::Put => update_realm(conn, realm, body),
        Method::Delete => delete_realm(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_realm_events(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_events(conn, realm, query),
        Method::Delete => delete_events(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_realm_session(
    conn: &Connection,
    method: &Method,
    realm: &str,
    session_id: &str,
    _query: &str,
) -> Result<Response> {
    match method {
        Method::Delete => delete_realm_session(conn, realm, session_id),
        _ => method_not_allowed(),
    }
}

fn handle_keys(conn: &Connection, method: &Method, realm: &str) -> Result<Response> {
    match method {
        Method::Get => get_keys(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_localizations(conn: &Connection, method: &Method, realm: &str) -> Result<Response> {
    match method {
        Method::Get => list_localizations(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_roles(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_roles(conn, realm, query),
        Method::Post => create_role(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_role_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    _query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(role_name) = tail.strip_suffix("/composites") {
        if !role_name.is_empty() && !role_name.contains('/') {
            return Ok(Some(handle_role_composites(
                conn, method, realm, role_name, None, body,
            )?));
        }
    }
    if let Some(role_name) = tail.strip_suffix("/composites/realm") {
        if !role_name.is_empty() && !role_name.contains('/') {
            return Ok(Some(handle_role_composites(
                conn, method, realm, role_name, Some("realm"), body,
            )?));
        }
    }
    if let Some((role_name, client_id)) = tail.split_once("/composites/clients/") {
        if !role_name.is_empty()
            && !role_name.contains('/')
            && !client_id.is_empty()
            && !client_id.contains('/')
        {
            return Ok(Some(handle_role_composites(
                conn, method, realm, role_name, Some("clients"), body,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_role(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_role_by_id_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    _query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(role_id) = tail.strip_suffix("/management/permissions") {
        if !role_id.is_empty() && !role_id.contains('/') {
            return Ok(Some(handle_role_by_id_permissions(
                conn, method, realm, role_id, body,
            )?));
        }
    }
    if let Some(role_id) = tail.strip_suffix("/composites") {
        if !role_id.is_empty() && !role_id.contains('/') {
            return Ok(Some(handle_role_by_id_composites(
                conn, method, realm, role_id, None, body,
            )?));
        }
    }
    if let Some(role_id) = tail.strip_suffix("/composites/realm") {
        if !role_id.is_empty() && !role_id.contains('/') {
            return Ok(Some(handle_role_by_id_composites(
                conn, method, realm, role_id, Some("realm"), body,
            )?));
        }
    }
    if let Some((role_id, client_id)) = tail.split_once("/composites/clients/") {
        if !role_id.is_empty()
            && !role_id.contains('/')
            && !client_id.is_empty()
            && !client_id.contains('/')
        {
            return Ok(Some(handle_role_by_id_composites(
                conn, method, realm, role_id, Some("clients"), body,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_role_by_id(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_role(
    conn: &Connection,
    method: &Method,
    realm: &str,
    role_name: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_role(conn, realm, role_name),
        Method::Put => update_role(conn, realm, role_name, body),
        Method::Delete => delete_role(conn, realm, role_name),
        _ => method_not_allowed(),
    }
}

fn handle_role_by_id(
    conn: &Connection,
    method: &Method,
    realm: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_role_by_id(conn, realm, role_id),
        Method::Put => update_role_by_id(conn, realm, role_id, body),
        Method::Delete => delete_role_by_id(conn, realm, role_id),
        _ => method_not_allowed(),
    }
}

fn handle_role_composites(
    conn: &Connection,
    method: &Method,
    realm: &str,
    role_name: &str,
    scope: Option<&str>,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_role_composites(conn, realm, role_name, scope),
        Method::Post => add_role_composites(conn, realm, role_name, body),
        Method::Delete => delete_role_composites(conn, realm, role_name, body),
        _ => method_not_allowed(),
    }
}

fn handle_role_by_id_composites(
    conn: &Connection,
    method: &Method,
    realm: &str,
    role_id: &str,
    scope: Option<&str>,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_role_by_id_composites(conn, realm, role_id, scope),
        Method::Post => add_role_by_id_composites(conn, realm, role_id, body),
        Method::Delete => delete_role_by_id_composites(conn, realm, role_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_role_by_id_permissions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_role_by_id_permissions(conn, realm, role_id),
        Method::Put => update_role_by_id_permissions(conn, realm, role_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_users(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_users(conn, realm, query),
        Method::Post => create_user(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_users_count(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => count_users(conn, realm, query),
        _ => method_not_allowed(),
    }
}

fn handle_users_profile(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_users_profile(conn, realm),
        Method::Put => update_users_profile(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_users_profile_metadata(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_users_profile_metadata(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_users_management_permissions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_users_management_permissions(conn, realm),
        Method::Put => update_users_management_permissions(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_user_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(user_id) = tail.strip_suffix("/sessions") {
        if !user_id.is_empty() && !user_id.contains('/') {
            return Ok(Some(handle_user_sessions(conn, method, realm, user_id)?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_user(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_user(
    conn: &Connection,
    method: &Method,
    realm: &str,
    user_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_user(conn, realm, user_id),
        Method::Put => update_user(conn, realm, user_id, body),
        Method::Delete => delete_user(conn, realm, user_id),
        _ => method_not_allowed(),
    }
}

fn handle_user_sessions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    user_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_user_sessions(conn, realm, user_id),
        _ => method_not_allowed(),
    }
}

fn handle_workflows(conn: &Connection, method: &Method, realm: &str) -> Result<Response> {
    match method {
        Method::Get => list_workflows(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_workflow(
    conn: &Connection,
    method: &Method,
    realm: &str,
    workflow_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_workflow(conn, realm, workflow_id),
        _ => method_not_allowed(),
    }
}

fn handle_workflows_scheduled(
    conn: &Connection,
    method: &Method,
    realm: &str,
    resource_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_workflow_scheduled(conn, realm, resource_id),
        _ => method_not_allowed(),
    }
}

fn handle_localization_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some((locale, key)) = tail.split_once('/') {
        if !locale.is_empty()
            && !locale.contains('/')
            && !key.is_empty()
            && !key.contains('/')
        {
            return Ok(Some(handle_localization_key(
                conn, method, realm, locale, key, body,
            )?));
        }
        return Ok(None);
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_localization_locale(
            conn, method, realm, tail, body,
        )?));
    }
    Ok(None)
}

fn handle_localization_locale(
    conn: &Connection,
    method: &Method,
    realm: &str,
    locale: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_localization_locale(conn, realm, locale),
        Method::Post => import_localization_locale(conn, realm, locale, body),
        Method::Delete => delete_localization_locale(conn, realm, locale),
        _ => method_not_allowed(),
    }
}

fn handle_localization_key(
    conn: &Connection,
    method: &Method,
    realm: &str,
    locale: &str,
    key: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_localization_key(conn, realm, locale, key),
        Method::Put => put_localization_key(conn, realm, locale, key, body),
        Method::Delete => delete_localization_key(conn, realm, locale, key),
        _ => method_not_allowed(),
    }
}

fn handle_organizations(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_organizations(conn, realm, query),
        Method::Post => create_organization(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_organizations_count(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => count_organizations(conn, realm, query),
        _ => method_not_allowed(),
    }
}

fn handle_organizations_for_member(
    conn: &Connection,
    method: &Method,
    realm: &str,
    member_id: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_organizations_for_member(conn, realm, member_id, query),
        _ => method_not_allowed(),
    }
}

fn handle_organization_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(org_id) = tail.strip_suffix("/identity-providers") {
        if !org_id.is_empty() && !org_id.contains('/') {
            return Ok(Some(handle_organization_identity_providers(
                conn, method, realm, org_id, body,
            )?));
        }
    }
    if let Some((org_id, alias)) = tail.split_once("/identity-providers/") {
        if !org_id.is_empty()
            && !org_id.contains('/')
            && !alias.is_empty()
            && !alias.contains('/')
        {
            return Ok(Some(handle_organization_identity_provider(
                conn, method, realm, org_id, alias,
            )?));
        }
    }
    if let Some(org_id) = tail.strip_suffix("/invitations") {
        if !org_id.is_empty() && !org_id.contains('/') {
            return Ok(Some(handle_organization_invitations(
                conn, method, realm, org_id, query,
            )?));
        }
    }
    if let Some((org_id, rest)) = tail.split_once("/invitations/") {
        if !org_id.is_empty() && !org_id.contains('/') && !rest.is_empty() {
            if let Some(invite_id) = rest.strip_suffix("/resend") {
                if !invite_id.is_empty() && !invite_id.contains('/') {
                    return Ok(Some(handle_organization_invitation_resend(
                        conn, method, realm, org_id, invite_id,
                    )?));
                }
            }
            if !rest.contains('/') {
                return Ok(Some(handle_organization_invitation(
                    conn, method, realm, org_id, rest,
                )?));
            }
        }
    }
    if let Some((org_id, rest)) = tail.split_once("/members/") {
        if !org_id.is_empty() && !org_id.contains('/') && !rest.is_empty() {
            if rest == "count" {
                return Ok(Some(handle_organization_members_count(
                    conn, method, realm, org_id,
                )?));
            }
            if rest == "invite-existing-user" {
                return Ok(Some(handle_organization_members_invite_existing(
                    conn, method, realm, org_id, body,
                )?));
            }
            if rest == "invite-user" {
                return Ok(Some(handle_organization_members_invite_user(
                    conn, method, realm, org_id, body,
                )?));
            }
            if let Some(member_id) = rest.strip_suffix("/organizations") {
                if !member_id.is_empty() && !member_id.contains('/') {
                    return Ok(Some(handle_organization_member_organizations(
                        conn, method, realm, org_id, member_id,
                    )?));
                }
            }
            if !rest.contains('/') {
                return Ok(Some(handle_organization_member(
                    conn, method, realm, org_id, rest,
                )?));
            }
        }
    }
    if let Some(org_id) = tail.strip_suffix("/members") {
        if !org_id.is_empty() && !org_id.contains('/') {
            return Ok(Some(handle_organization_members(
                conn, method, realm, org_id, query, body,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_organization(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_organization(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_organization(conn, realm, org_id),
        Method::Put => update_organization(conn, realm, org_id, body),
        Method::Delete => delete_organization(conn, realm, org_id),
        _ => method_not_allowed(),
    }
}

fn handle_organization_identity_providers(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_organization_identity_providers(conn, realm, org_id),
        Method::Post => add_organization_identity_provider(conn, realm, org_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_organization_identity_provider(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    alias: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_organization_identity_provider(conn, realm, org_id, alias),
        Method::Delete => delete_organization_identity_provider(conn, realm, org_id, alias),
        _ => method_not_allowed(),
    }
}

fn handle_organization_invitations(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_organization_invitations(conn, realm, org_id, query),
        _ => method_not_allowed(),
    }
}

fn handle_organization_invitation(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    invitation_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_organization_invitation(conn, realm, org_id, invitation_id),
        Method::Delete => delete_organization_invitation(conn, realm, org_id, invitation_id),
        _ => method_not_allowed(),
    }
}

fn handle_organization_invitation_resend(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    invitation_id: &str,
) -> Result<Response> {
    match method {
        Method::Post => resend_organization_invitation(conn, realm, org_id, invitation_id),
        _ => method_not_allowed(),
    }
}

fn handle_organization_members(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_organization_members(conn, realm, org_id, query),
        Method::Post => add_organization_member(conn, realm, org_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_organization_members_count(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => count_organization_members(conn, realm, org_id),
        _ => method_not_allowed(),
    }
}

fn handle_organization_members_invite_existing(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => invite_existing_member(conn, realm, org_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_organization_members_invite_user(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => invite_member(conn, realm, org_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_organization_member(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    member_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_organization_member(conn, realm, org_id, member_id),
        Method::Delete => delete_organization_member(conn, realm, org_id, member_id),
        _ => method_not_allowed(),
    }
}

fn handle_organization_member_organizations(
    conn: &Connection,
    method: &Method,
    realm: &str,
    org_id: &str,
    member_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_member_organizations(conn, realm, org_id, member_id),
        _ => method_not_allowed(),
    }
}

fn handle_clients(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_clients(conn, realm, query),
        Method::Post => create_client(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_components(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_components(conn, realm, query),
        Method::Post => create_component(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_component_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(component_id) = tail.strip_suffix("/sub-component-types") {
        if !component_id.is_empty() && !component_id.contains('/') {
            return Ok(Some(handle_component_subtypes(
                conn,
                method,
                realm,
                component_id,
                query,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_component(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_component(
    conn: &Connection,
    method: &Method,
    realm: &str,
    component_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_component(conn, realm, component_id),
        Method::Put => update_component(conn, realm, component_id, body),
        Method::Delete => delete_component(conn, realm, component_id),
        _ => method_not_allowed(),
    }
}

fn handle_component_subtypes(
    conn: &Connection,
    method: &Method,
    realm: &str,
    component_id: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_component_subtypes(conn, realm, component_id, query),
        _ => method_not_allowed(),
    }
}

fn handle_groups(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_groups(conn, realm, query),
        Method::Post => create_group(conn, realm, body, None),
        _ => method_not_allowed(),
    }
}

fn handle_groups_count(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_groups_count(conn, realm, query),
        _ => method_not_allowed(),
    }
}

fn handle_group_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(group_id) = tail.strip_suffix("/children") {
        if !group_id.is_empty() && !group_id.contains('/') {
            return Ok(Some(handle_group_children(
                conn, method, realm, group_id, query, body,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_group(conn, method, realm, tail, body)?));
    }
    Ok(None)
}

fn handle_group(
    conn: &Connection,
    method: &Method,
    realm: &str,
    group_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_group(conn, realm, group_id),
        Method::Put => update_group(conn, realm, group_id, body),
        Method::Delete => delete_group(conn, realm, group_id),
        _ => method_not_allowed(),
    }
}

fn handle_group_children(
    conn: &Connection,
    method: &Method,
    realm: &str,
    group_id: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_group_children(conn, realm, group_id, query),
        Method::Post => create_group(conn, realm, body, Some(group_id)),
        _ => method_not_allowed(),
    }
}

fn handle_group_by_path(
    conn: &Connection,
    method: &Method,
    realm: &str,
    path: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_group_by_path(conn, realm, path),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_instances(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_identity_providers(conn, realm, query),
        Method::Post => create_identity_provider(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_import_config(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => import_identity_provider_config(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_upload_certificate(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => upload_identity_provider_certificate(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_instance_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    _query: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(alias) = tail.strip_suffix("/management/permissions") {
        if !alias.is_empty() && !alias.contains('/') {
            return Ok(Some(handle_identity_provider_permissions(
                conn, method, realm, alias, body,
            )?));
        }
    }
    if let Some(alias) = tail.strip_suffix("/mapper-types") {
        if !alias.is_empty() && !alias.contains('/') {
            return Ok(Some(handle_identity_provider_mapper_types(
                conn, method, realm, alias,
            )?));
        }
    }
    if let Some(alias) = tail.strip_suffix("/mappers") {
        if !alias.is_empty() && !alias.contains('/') {
            return Ok(Some(handle_identity_provider_mappers(
                conn, method, realm, alias, body,
            )?));
        }
    }
    if let Some((alias, mapper_id)) = tail.split_once("/mappers/") {
        if !alias.is_empty()
            && !alias.contains('/')
            && !mapper_id.is_empty()
            && !mapper_id.contains('/')
        {
            return Ok(Some(handle_identity_provider_mapper(
                conn, method, realm, alias, mapper_id, body,
            )?));
        }
    }
    if let Some(alias) = tail.strip_suffix("/export") {
        if !alias.is_empty() && !alias.contains('/') {
            return Ok(Some(handle_identity_provider_export(
                conn, method, realm, alias,
            )?));
        }
    }
    if let Some(alias) = tail.strip_suffix("/reload-keys") {
        if !alias.is_empty() && !alias.contains('/') {
            return Ok(Some(handle_identity_provider_reload_keys(
                conn, method, realm, alias,
            )?));
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_identity_provider_instance(
            conn, method, realm, tail, body,
        )?));
    }
    Ok(None)
}

fn handle_identity_provider_instance(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_identity_provider(conn, realm, alias),
        Method::Put => update_identity_provider(conn, realm, alias, body),
        Method::Delete => delete_identity_provider(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_permissions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_identity_provider_permissions(conn, realm, alias),
        Method::Put => update_identity_provider_permissions(conn, realm, alias, body),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_mapper_types(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_identity_provider_mapper_types(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_mappers(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_identity_provider_mappers(conn, realm, alias),
        Method::Post => create_identity_provider_mapper(conn, realm, alias, body),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_mapper(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    mapper_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_identity_provider_mapper(conn, realm, alias, mapper_id),
        Method::Put => update_identity_provider_mapper(conn, realm, alias, mapper_id, body),
        Method::Delete => delete_identity_provider_mapper(conn, realm, alias, mapper_id),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_export(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    match method {
        Method::Get => export_identity_provider(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_reload_keys(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    match method {
        Method::Get => reload_identity_provider_keys(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_identity_provider_provider(
    conn: &Connection,
    method: &Method,
    realm: &str,
    provider_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_identity_provider_factory(conn, realm, provider_id),
        _ => method_not_allowed(),
    }
}

fn handle_client(
    conn: &Connection,
    method: &Method,
    realm: &str,
    client_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_client(conn, realm, client_id),
        Method::Put => update_client(conn, realm, client_id, body),
        Method::Delete => delete_client(conn, realm, client_id),
        _ => method_not_allowed(),
    }
}

fn handle_clients_initial_access(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_client_initial_access(conn, realm),
        Method::Post => create_client_initial_access(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_client_initial_access(
    conn: &Connection,
    method: &Method,
    realm: &str,
    token_id: &str,
) -> Result<Response> {
    match method {
        Method::Delete => delete_client_initial_access(conn, realm, token_id),
        _ => method_not_allowed(),
    }
}

fn handle_client_description_converter(
    conn: &Connection,
    method: &Method,
    realm: &str,
    _body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => convert_client_description(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_client_policies(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_client_policies(conn, realm),
        Method::Put => update_client_policies(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_client_profiles(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_client_profiles(conn, realm),
        Method::Put => update_client_profiles(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_client_registration_providers(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_client_registration_providers(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_client_session_stats(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_client_session_stats(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_credential_registrators(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_credential_registrators(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_client_types(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_client_types(conn, realm),
        Method::Put => update_client_types(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_client_scopes(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_client_scopes(conn, realm),
        Method::Post => create_client_scope(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_client_templates(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    handle_client_scopes(conn, method, realm, body)
}

fn handle_client_scope_paths(
    conn: &Connection,
    method: &Method,
    realm: &str,
    tail: &str,
    body: &[u8],
) -> Result<Option<Response>> {
    if let Some(scope_id) = tail.strip_suffix("/protocol-mappers/add-models") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_protocol_mappers_add_models(
                conn, method, realm, scope_id, body,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/protocol-mappers/models") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_protocol_mappers(
                conn, method, realm, scope_id, body,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/protocol-mappers/protocol") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(method_not_allowed()?));
        }
    }
    if let Some((scope_id, protocol)) = tail.split_once("/protocol-mappers/protocol/") {
        if !scope_id.is_empty()
            && !scope_id.contains('/')
            && !protocol.is_empty()
            && !protocol.contains('/')
        {
            return Ok(Some(handle_protocol_mappers_by_protocol(
                conn, method, realm, scope_id, protocol,
            )?));
        }
    }
    if let Some((scope_id, mapper_id)) = tail.split_once("/protocol-mappers/models/") {
        if !scope_id.is_empty()
            && !scope_id.contains('/')
            && !mapper_id.is_empty()
            && !mapper_id.contains('/')
        {
            return Ok(Some(handle_protocol_mapper(
                conn, method, realm, scope_id, mapper_id, body,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/scope-mappings") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_scope_mappings(
                conn, method, realm, scope_id,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/scope-mappings/realm") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_scope_mapping_realm(
                conn, method, realm, scope_id,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/scope-mappings/realm/available") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_scope_mapping_realm_list(
                conn, method, realm, scope_id,
            )?));
        }
    }
    if let Some(scope_id) = tail.strip_suffix("/scope-mappings/realm/composite") {
        if !scope_id.is_empty() && !scope_id.contains('/') {
            return Ok(Some(handle_scope_mapping_realm_list(
                conn, method, realm, scope_id,
            )?));
        }
    }
    if let Some((scope_id, client_id)) = tail.split_once("/scope-mappings/clients/") {
        if !scope_id.is_empty() && !scope_id.contains('/') && !client_id.is_empty() {
            if let Some(client_name) = client_id.strip_suffix("/available") {
                if !client_name.is_empty() && !client_name.contains('/') {
                    return Ok(Some(handle_scope_mapping_client_list(
                        conn, method, realm, scope_id, client_name,
                    )?));
                }
            }
            if let Some(client_name) = client_id.strip_suffix("/composite") {
                if !client_name.is_empty() && !client_name.contains('/') {
                    return Ok(Some(handle_scope_mapping_client_list(
                        conn, method, realm, scope_id, client_name,
                    )?));
                }
            }
            if !client_id.contains('/') {
                return Ok(Some(handle_scope_mapping_client(
                    conn, method, realm, scope_id, client_id,
                )?));
            }
        }
    }
    if !tail.is_empty() && !tail.contains('/') {
        return Ok(Some(handle_client_scope(
            conn, method, realm, tail, body,
        )?));
    }
    Ok(None)
}

fn handle_client_scope(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_client_scope(conn, realm, scope_id),
        Method::Put => update_client_scope(conn, realm, scope_id, body),
        Method::Delete => delete_client_scope(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_protocol_mappers_add_models(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => add_protocol_mappers(conn, realm, scope_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_protocol_mappers(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_protocol_mappers(conn, realm, scope_id, None),
        Method::Post => create_protocol_mapper(conn, realm, scope_id, body),
        _ => method_not_allowed(),
    }
}

fn handle_protocol_mappers_by_protocol(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    protocol: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_protocol_mappers(conn, realm, scope_id, Some(protocol)),
        _ => method_not_allowed(),
    }
}

fn handle_protocol_mapper(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    mapper_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_protocol_mapper(conn, realm, scope_id, mapper_id),
        Method::Put => update_protocol_mapper(conn, realm, scope_id, mapper_id, body),
        Method::Delete => delete_protocol_mapper(conn, realm, scope_id, mapper_id),
        _ => method_not_allowed(),
    }
}

fn handle_scope_mappings(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_scope_mappings(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_scope_mapping_client(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    _client_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_scope_mapping_client(conn, realm, scope_id),
        Method::Post => update_scope_mapping_client(conn, realm, scope_id),
        Method::Delete => update_scope_mapping_client(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_scope_mapping_client_list(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
    _client_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_scope_mapping_client(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_scope_mapping_realm(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_scope_mapping_realm(conn, realm, scope_id),
        Method::Post => update_scope_mapping_realm(conn, realm, scope_id),
        Method::Delete => update_scope_mapping_realm(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_scope_mapping_realm_list(
    conn: &Connection,
    method: &Method,
    realm: &str,
    scope_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_scope_mapping_realm(conn, realm, scope_id),
        _ => method_not_allowed(),
    }
}

fn handle_admin_events(
    conn: &Connection,
    method: &Method,
    realm: &str,
    query: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_admin_events(conn, realm, query),
        Method::Delete => delete_admin_events(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_events_config(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_events_config(conn, realm),
        Method::Put => update_events_config(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_auth_flows(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_auth_flows(conn, realm),
        Method::Post => create_auth_flow(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_auth_flow_by_id(
    conn: &Connection,
    method: &Method,
    realm: &str,
    flow_id: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_auth_flow(conn, realm, flow_id),
        Method::Put => update_auth_flow(conn, realm, flow_id, body),
        Method::Delete => delete_auth_flow(conn, realm, flow_id),
        _ => method_not_allowed(),
    }
}

fn handle_auth_flow_executions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    flow_alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => list_auth_flow_executions(conn, realm, flow_alias),
        Method::Put => update_auth_flow_execution(conn, realm, flow_alias, body),
        _ => method_not_allowed(),
    }
}

fn handle_auth_providers(conn: &Connection, method: &Method, realm: &str) -> Result<Response> {
    match method {
        Method::Get => list_auth_providers(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_unregistered_required_actions(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Get => list_unregistered_required_actions(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_register_required_action(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => register_required_action(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_required_actions(conn: &Connection, method: &Method, realm: &str) -> Result<Response> {
    match method {
        Method::Get => list_required_actions(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_required_action(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_required_action(conn, realm, alias),
        Method::Put => update_required_action(conn, realm, alias, body),
        Method::Delete => delete_required_action(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_required_action_config(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_required_action_config(conn, realm, alias),
        Method::Put => update_required_action_config(conn, realm, alias, body),
        Method::Delete => delete_required_action_config_endpoint(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_required_action_config_description(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_required_action_config_description(conn, realm, alias),
        _ => method_not_allowed(),
    }
}

fn handle_required_action_priority(
    conn: &Connection,
    method: &Method,
    realm: &str,
    alias: &str,
    delta: i64,
) -> Result<Response> {
    match method {
        Method::Post => update_required_action_priority(conn, realm, alias, delta),
        _ => method_not_allowed(),
    }
}

fn handle_auth_executions(
    conn: &Connection,
    method: &Method,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => create_auth_execution(conn, realm, body),
        _ => method_not_allowed(),
    }
}

fn handle_auth_execution(
    conn: &Connection,
    method: &Method,
    realm: &str,
    exec_id: &str,
    _body: &[u8],
) -> Result<Response> {
    match method {
        Method::Get => get_auth_execution(conn, realm, exec_id),
        Method::Delete => delete_auth_execution(conn, realm, exec_id),
        _ => method_not_allowed(),
    }
}

fn handle_auth_execution_config(
    conn: &Connection,
    method: &Method,
    realm: &str,
    exec_id: &str,
    config_id: Option<&str>,
    body: &[u8],
) -> Result<Response> {
    match method {
        Method::Post => create_auth_execution_config(conn, realm, exec_id, body),
        Method::Get => get_auth_execution_config(conn, realm, exec_id, config_id),
        _ => method_not_allowed(),
    }
}

fn handle_auth_execution_priority(
    conn: &Connection,
    method: &Method,
    realm: &str,
    exec_id: &str,
    delta: i64,
) -> Result<Response> {
    match method {
        Method::Post => update_auth_execution_priority(conn, realm, exec_id, delta),
        _ => method_not_allowed(),
    }
}

fn handle_brute_force_all(
    conn: &Connection,
    method: &Method,
    realm: &str,
) -> Result<Response> {
    match method {
        Method::Delete => clear_brute_force_all(conn, realm),
        _ => method_not_allowed(),
    }
}

fn handle_brute_force_user(
    conn: &Connection,
    method: &Method,
    realm: &str,
    user_id: &str,
) -> Result<Response> {
    match method {
        Method::Get => get_brute_force_status(conn, realm, user_id),
        Method::Delete => clear_brute_force_user(conn, realm, user_id),
        _ => method_not_allowed(),
    }
}

fn list_realms(conn: &Connection, query: &str) -> Result<Response> {
    let brief = query_param(query, "briefRepresentation").as_deref() == Some("true");
    let rows = conn
        .execute("SELECT ID, NAME, ENABLED FROM REALM ORDER BY NAME", &[])
        .context("list realms")?;

    let mut items = Vec::new();
    for row in rows.rows() {
        let id = row.get::<&str>("ID").unwrap_or_default().to_string();
        let realm = row.get::<&str>("NAME").unwrap_or_default().to_string();
        if brief {
            let enabled = row
                .get::<i64>("ENABLED")
                .map(|v| v != 0)
                .unwrap_or(false);
            items.push(json!({"realm": realm, "id": id, "enabled": enabled}));
        } else {
            items.push(load_realm(conn, &id, &realm)?);
        }
    }

    json_response(200, JsonValue::Array(items))
}

fn list_clients(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let client_id_filter = first_param(&params, "clientId");
    let first = int_param(&params, "first").unwrap_or(0);
    let max = int_param(&params, "max");

    let mut sql = "SELECT ID, CLIENT_ID FROM CLIENT WHERE REALM_ID=?1".to_string();
    let mut values = vec![SqlValue::Text(realm_id.clone())];
    if let Some(client_id) = client_id_filter.clone() {
        sql.push_str(" AND CLIENT_ID=?2");
        values.push(SqlValue::Text(client_id));
    }
    sql.push_str(" ORDER BY CLIENT_ID");
    if let Some(limit) = max {
        sql.push_str(&format!(" LIMIT {limit}"));
        if first > 0 {
            sql.push_str(&format!(" OFFSET {first}"));
        }
    } else if first > 0 {
        sql.push_str(&format!(" LIMIT -1 OFFSET {first}"));
    }

    let rows = conn.execute(&sql, &values).context("list clients")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(client_uuid) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(client) = load_client_by_id(conn, &realm_id, client_uuid)? {
            items.push(client);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_client(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let client_id = match value.get("clientId").and_then(|v| v.as_str()) {
        Some(client_id) => client_id.to_string(),
        None => return json_response(400, json!({"error": "clientId is required"})),
    };
    let client_uuid = value
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&client_id)
        .to_string();

    if client_id_exists(conn, &realm_id, &client_id)? {
        return json_response(409, json!({"error": "clientId already exists"}));
    }
    if client_uuid_exists(conn, &client_uuid)? {
        return json_response(409, json!({"error": "client already exists"}));
    }

    value["id"] = JsonValue::String(client_uuid.clone());
    value["clientId"] = JsonValue::String(client_id.clone());

    execute_transaction(conn, |conn| {
        insert_client(conn, &realm_id, &client_uuid, &client_id, &value)?;
        insert_client_children(conn, &client_uuid, &value)?;
        Ok(())
    })
    .context("insert client")?;

    json_response(201, json!({"status": "created"}))
}

fn get_client(conn: &Connection, realm: &str, client_uuid: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(client) = load_client_by_id(conn, &realm_id, client_uuid)? else {
        return json_response(404, json!({"error": "client not found"}));
    };
    json_response(200, client)
}

fn update_client(
    conn: &Connection,
    realm: &str,
    client_uuid: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_client_by_id(conn, &realm_id, client_uuid)? {
        Some(client) => client,
        None => return json_response(404, json!({"error": "client not found"})),
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(client_uuid.to_string());

    if let Some(next_client_id) = patch.get("clientId").and_then(|v| v.as_str()) {
        let current_client_id = current.get("clientId").and_then(|v| v.as_str());
        if current_client_id != Some(next_client_id)
            && client_id_exists(conn, &realm_id, next_client_id)?
        {
            return json_response(409, json!({"error": "clientId already exists"}));
        }
    }

    execute_transaction(conn, |conn| {
        update_client_row(conn, &realm_id, client_uuid, &current)?;
        update_client_children(conn, client_uuid, &patch, &current)?;
        Ok(())
    })
    .context("update client")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_client(conn: &Connection, realm: &str, client_uuid: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(_) = load_client_by_id(conn, &realm_id, client_uuid)? else {
        return json_response(404, json!({"error": "client not found"}));
    };
    execute_transaction(conn, |conn| {
        delete_client_children(conn, client_uuid)?;
        conn.execute(
            "DELETE FROM CLIENT WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(client_uuid.to_string()), SqlValue::Text(realm_id)],
        )
        .context("delete client")?;
        Ok(())
    })?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_client_initial_access(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID, COUNT, REMAINING_COUNT, TIMESTAMP, EXPIRATION FROM CLIENT_INITIAL_ACCESS WHERE REALM_ID=?1 ORDER BY TIMESTAMP DESC",
            &[SqlValue::Text(realm_id)],
        )
        .context("list client initial access")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut item = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut item, "id", row.get::<&str>("ID"));
        set_opt_int(&mut item, "count", row.get::<i64>("COUNT"));
        set_opt_int(&mut item, "remainingCount", row.get::<i64>("REMAINING_COUNT"));
        set_opt_int(&mut item, "timestamp", row.get::<i64>("TIMESTAMP"));
        set_opt_int(&mut item, "expiration", row.get::<i64>("EXPIRATION"));
        items.push(item);
    }
    json_response(200, JsonValue::Array(items))
}

fn create_client_initial_access(
    conn: &Connection,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let count = match value.get("count").and_then(|v| v.as_i64()) {
        Some(count) => count,
        None => return json_response(400, json!({"error": "count is required"})),
    };
    let expiration = value.get("expiration").and_then(|v| v.as_i64()).unwrap_or(0);

    let id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("cia"));
    let timestamp = current_epoch_seconds();

    conn.execute(
        "INSERT INTO CLIENT_INITIAL_ACCESS (ID, REALM_ID, COUNT, REMAINING_COUNT, TIMESTAMP, EXPIRATION) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            SqlValue::Text(id.clone()),
            SqlValue::Text(realm_id),
            SqlValue::Integer(count),
            SqlValue::Integer(count),
            SqlValue::Integer(timestamp),
            SqlValue::Integer(expiration),
        ],
    )
    .context("insert client initial access")?;

    json_response(
        201,
        json!({
            "id": id,
            "count": count,
            "remainingCount": count,
            "timestamp": timestamp,
            "expiration": expiration
        }),
    )
}

fn delete_client_initial_access(
    conn: &Connection,
    realm: &str,
    token_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT_INITIAL_ACCESS WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(token_id.to_string()), SqlValue::Text(realm_id.clone())],
        )
        .context("check client initial access")?;
    if rows.rows().next().is_none() {
        return json_response(404, json!({"error": "token not found"}));
    }
    conn.execute(
        "DELETE FROM CLIENT_INITIAL_ACCESS WHERE ID=?1 AND REALM_ID=?2",
        &[SqlValue::Text(token_id.to_string()), SqlValue::Text(realm_id)],
    )
    .context("delete client initial access")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn convert_client_description(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_client_policies(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn update_client_policies(conn: &Connection, realm: &str, _body: &[u8]) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_client_profiles(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn update_client_profiles(conn: &Connection, realm: &str, _body: &[u8]) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_client_registration_providers(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn get_client_session_stats(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_client_types(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn update_client_types(conn: &Connection, realm: &str, _body: &[u8]) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_credential_registrators(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT DISTINCT TYPE FROM REALM_REQUIRED_CREDENTIAL WHERE REALM_ID=?1 ORDER BY TYPE",
            &[SqlValue::Text(realm_id)],
        )
        .context("list credential registrators")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        if let Some(cred_type) = row.get::<&str>("TYPE") {
            items.push(JsonValue::String(cred_type.to_string()));
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn list_groups(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let search = first_param(&params, "search").or_else(|| first_param(&params, "q"));
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let brief = first_param(&params, "briefRepresentation")
        .map(|v| v == "true")
        .unwrap_or(true);
    let populate_hierarchy = first_param(&params, "populateHierarchy")
        .map(|v| v == "true")
        .unwrap_or(true);
    let include_subgroup_count = first_param(&params, "subGroupsCount")
        .map(|v| v == "true")
        .unwrap_or(true);

    let mut sql =
        "SELECT ID, NAME FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND PARENT_GROUP IS NULL"
            .to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];
    if let Some(term) = search.clone() {
        if exact {
            sql.push_str(&format!(" AND NAME = ?{}", values.len() + 1));
            values.push(SqlValue::Text(term));
        } else {
            sql.push_str(&format!(" AND NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    sql.push_str(" ORDER BY NAME");

    let max = int_param(&params, "max").unwrap_or(100).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);
    sql.push_str(&format!(" LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list groups")?;
    let mut items = Vec::new();
    let include_subgroups = !brief && populate_hierarchy;
    for row in rows.rows() {
        let Some(group_id) = row.get::<&str>("ID") else {
            continue;
        };
        if brief {
            let mut group = JsonValue::Object(serde_json::Map::new());
            set_opt_string(&mut group, "id", row.get::<&str>("ID"));
            set_opt_string(&mut group, "name", row.get::<&str>("NAME"));
            items.push(group);
        } else if let Some(group) = load_group_representation(
            conn,
            &realm_id,
            group_id,
            include_subgroups,
            include_subgroup_count,
        )? {
            items.push(group);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn list_group_children(
    conn: &Connection,
    realm: &str,
    group_id: &str,
    query: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !group_in_realm(conn, &realm_id, group_id)? {
        return json_response(404, json!({"error": "group not found"}));
    }
    let params = parse_query_params(query);
    let search = first_param(&params, "search");
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let brief = first_param(&params, "briefRepresentation")
        .map(|v| v == "true")
        .unwrap_or(false);
    let include_subgroup_count = first_param(&params, "subGroupsCount")
        .map(|v| v == "true")
        .unwrap_or(true);

    let max = int_param(&params, "max").unwrap_or(10).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);

    let mut sql = "SELECT ID, NAME FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND PARENT_GROUP=?2"
        .to_string();
    let mut values: Vec<SqlValue> = vec![
        SqlValue::Text(realm_id.clone()),
        SqlValue::Text(group_id.to_string()),
    ];
    if let Some(term) = search.clone() {
        if exact {
            sql.push_str(&format!(" AND NAME = ?{}", values.len() + 1));
            values.push(SqlValue::Text(term));
        } else {
            sql.push_str(&format!(" AND NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    sql.push_str(&format!(" ORDER BY NAME LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list group children")?;
    let mut items = Vec::new();
    let include_subgroups = !brief;
    for row in rows.rows() {
        let Some(child_id) = row.get::<&str>("ID") else {
            continue;
        };
        if brief {
            let mut group = JsonValue::Object(serde_json::Map::new());
            set_opt_string(&mut group, "id", row.get::<&str>("ID"));
            set_opt_string(&mut group, "name", row.get::<&str>("NAME"));
            items.push(group);
        } else if let Some(group) = load_group_representation(
            conn,
            &realm_id,
            child_id,
            include_subgroups,
            include_subgroup_count,
        )? {
            items.push(group);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_group(
    conn: &Connection,
    realm: &str,
    body: &[u8],
    parent_override: Option<&str>,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return json_response(400, json!({"error": "name is required"})),
    };
    let group_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("group"));
    if group_id_exists(conn, &group_id)? {
        return json_response(409, json!({"error": "group already exists"}));
    }

    let parent_id = parent_override
        .map(|v| v.to_string())
        .or_else(|| value.get("parentId").and_then(|v| v.as_str()).map(|v| v.to_string()));
    if let Some(parent_id) = parent_id.as_deref() {
        if !group_in_realm(conn, &realm_id, parent_id)? {
            return json_response(404, json!({"error": "parent group not found"}));
        }
    }

    value["id"] = JsonValue::String(group_id.clone());
    value["name"] = JsonValue::String(name.clone());
    if let Some(parent_id) = parent_id.as_deref() {
        value["parentId"] = JsonValue::String(parent_id.to_string());
    }

    execute_transaction(conn, |conn| {
        insert_group(conn, &realm_id, &group_id, &value)?;
        insert_group_attributes(conn, &group_id, &value)?;
        Ok(())
    })
    .context("insert group")?;

    let group = load_group_representation(conn, &realm_id, &group_id, true, false)?
        .ok_or_else(|| anyhow!("group not found after create"))?;
    json_response(201, group)
}

fn get_group(conn: &Connection, realm: &str, group_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(group) = load_group_representation(conn, &realm_id, group_id, true, true)? else {
        return json_response(404, json!({"error": "group not found"}));
    };
    json_response(200, group)
}

fn update_group(conn: &Connection, realm: &str, group_id: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_group_representation(conn, &realm_id, group_id, true, false)? {
        Some(group) => group,
        None => return json_response(404, json!({"error": "group not found"})),
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(group_id.to_string());

    if let Some(parent_id) = patch.get("parentId").and_then(|v| v.as_str()) {
        if !parent_id.is_empty() && !group_in_realm(conn, &realm_id, parent_id)? {
            return json_response(404, json!({"error": "parent group not found"}));
        }
    }

    execute_transaction(conn, |conn| {
        update_group_row(conn, &realm_id, group_id, &current)?;
        if has_key(&patch, "attributes") {
            delete_group_attributes(conn, group_id)?;
            insert_group_attributes(conn, group_id, &current)?;
        }
        Ok(())
    })
    .context("update group")?;

    json_response(204, JsonValue::Null)
}

fn delete_group(conn: &Connection, realm: &str, group_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !group_in_realm(conn, &realm_id, group_id)? {
        return json_response(404, json!({"error": "group not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_group_recursive(conn, &realm_id, group_id)?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_group_by_path(conn: &Connection, realm: &str, path: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return json_response(404, json!({"error": "group not found"}));
    }
    let mut current_parent: Option<String> = None;
    let mut found_id: Option<String> = None;
    for segment in trimmed.split('/') {
        let group_id = find_group_by_name_parent(conn, &realm_id, segment, current_parent.as_deref())?;
        let Some(group_id) = group_id else {
            return json_response(404, json!({"error": "group not found"}));
        };
        current_parent = Some(group_id.clone());
        found_id = Some(group_id);
    }
    let Some(group_id) = found_id else {
        return json_response(404, json!({"error": "group not found"}));
    };
    let Some(group) = load_group_representation(conn, &realm_id, &group_id, true, true)? else {
        return json_response(404, json!({"error": "group not found"}));
    };
    json_response(200, group)
}

fn get_groups_count(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let search = first_param(&params, "search");
    let top = first_param(&params, "top").map(|v| v == "true").unwrap_or(false);
    let mut sql = "SELECT COUNT(*) AS CNT FROM KEYCLOAK_GROUP WHERE REALM_ID=?1".to_string();
    let mut values = vec![SqlValue::Text(realm_id)];
    if let Some(term) = search {
        sql.push_str(&format!(" AND NAME LIKE ?{}", values.len() + 1));
        values.push(SqlValue::Text(format!("%{term}%")));
    }
    if top {
        sql.push_str(" AND PARENT_GROUP IS NULL");
    }
    let rows = conn.execute(&sql, &values).context("count groups")?;
    let mut count = 0;
    if let Some(row) = rows.rows().next() {
        count = row.get::<i64>("CNT").unwrap_or(0);
    }
    json_response(200, json!({"count": count}))
}

fn list_identity_providers(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let brief = first_param(&params, "briefRepresentation")
        .map(|v| v == "true")
        .unwrap_or(false);
    let search = first_param(&params, "search");
    let provider_type = first_param(&params, "type");
    let realm_only = first_param(&params, "realmOnly")
        .map(|v| v == "true")
        .unwrap_or(false);
    let max = int_param(&params, "max").unwrap_or(100).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);

    let mut sql = "SELECT INTERNAL_ID, PROVIDER_ALIAS, PROVIDER_DISPLAY_NAME, PROVIDER_ID, ENABLED, ORGANIZATION_ID FROM IDENTITY_PROVIDER WHERE REALM_ID=?1"
        .to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];
    if let Some(term) = search.clone() {
        sql.push_str(&format!(" AND (PROVIDER_ALIAS LIKE ?{} OR PROVIDER_DISPLAY_NAME LIKE ?{})", values.len() + 1, values.len() + 2));
        values.push(SqlValue::Text(format!("%{term}%")));
        values.push(SqlValue::Text(format!("%{term}%")));
    }
    if let Some(provider_type) = provider_type {
        sql.push_str(&format!(" AND PROVIDER_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(provider_type));
    }
    if realm_only {
        sql.push_str(" AND ORGANIZATION_ID IS NULL");
    }
    sql.push_str(" ORDER BY PROVIDER_ALIAS");
    sql.push_str(&format!(" LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list identity providers")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(alias) = row.get::<&str>("PROVIDER_ALIAS") else {
            continue;
        };
        if brief {
            let mut value = JsonValue::Object(serde_json::Map::new());
            set_opt_string(&mut value, "alias", row.get::<&str>("PROVIDER_ALIAS"));
            set_opt_string(&mut value, "displayName", row.get::<&str>("PROVIDER_DISPLAY_NAME"));
            set_opt_string(&mut value, "providerId", row.get::<&str>("PROVIDER_ID"));
            set_opt_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
            items.push(value);
        } else if let Some(value) = load_identity_provider_by_alias(conn, &realm_id, alias)? {
            items.push(value);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_identity_provider(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let alias = match value.get("alias").and_then(|v| v.as_str()) {
        Some(alias) => alias.to_string(),
        None => return json_response(400, json!({"error": "alias is required"})),
    };
    let provider_id = match value.get("providerId").and_then(|v| v.as_str()) {
        Some(provider_id) => provider_id.to_string(),
        None => return json_response(400, json!({"error": "providerId is required"})),
    };
    if identity_provider_alias_exists(conn, &realm_id, &alias)? {
        return json_response(409, json!({"error": "identity provider already exists"}));
    }

    let internal_id = value
        .get("internalId")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("idp"));
    value["alias"] = JsonValue::String(alias.clone());
    value["providerId"] = JsonValue::String(provider_id);
    value["internalId"] = JsonValue::String(internal_id.clone());

    execute_transaction(conn, |conn| {
        insert_identity_provider(conn, &realm_id, &internal_id, &value)?;
        insert_identity_provider_config(conn, &internal_id, &value)?;
        Ok(())
    })
    .context("insert identity provider")?;

    let provider = load_identity_provider_by_alias(conn, &realm_id, &alias)?
        .ok_or_else(|| anyhow!("identity provider not found after create"))?;
    json_response(201, provider)
}

fn get_identity_provider(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    json_response(200, provider)
}

fn update_identity_provider(
    conn: &Connection,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_identity_provider_by_alias(conn, &realm_id, alias)? {
        Some(provider) => provider,
        None => return json_response(404, json!({"error": "identity provider not found"})),
    };
    merge_json(&mut current, &patch);
    current["alias"] = JsonValue::String(alias.to_string());

    let internal_id = current
        .get("internalId")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .ok_or_else(|| anyhow!("internalId missing"))?;

    execute_transaction(conn, |conn| {
        update_identity_provider_row(conn, &realm_id, &internal_id, &current)?;
        if has_key(&patch, "config") {
            delete_identity_provider_config(conn, &internal_id)?;
            insert_identity_provider_config(conn, &internal_id, &current)?;
        }
        Ok(())
    })
    .context("update identity provider")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_identity_provider(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    let internal_id = provider
        .get("internalId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    execute_transaction(conn, |conn| {
        delete_identity_provider_config(conn, internal_id)?;
        delete_identity_provider_mappers(conn, &realm_id, alias)?;
        conn.execute(
            "DELETE FROM IDENTITY_PROVIDER WHERE REALM_ID=?1 AND PROVIDER_ALIAS=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("delete identity provider")?;
        Ok(())
    })?;
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn import_identity_provider_config(
    conn: &Connection,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let Some(obj) = value.as_object() else {
        return json_response(200, JsonValue::Object(serde_json::Map::new()));
    };
    let mut config = serde_json::Map::new();
    for (key, val) in obj {
        config.insert(key.clone(), JsonValue::String(json_to_string(val)));
    }
    json_response(200, JsonValue::Object(config))
}

fn upload_identity_provider_certificate(
    conn: &Connection,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    json_response(200, value)
}

fn export_identity_provider(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    json_response(200, provider)
}

fn reload_identity_provider_keys(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let response = json!({"reloaded": false, "alias": alias});
    json_response(200, response)
}

fn get_identity_provider_permissions(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_identity_provider_by_alias(conn, &realm_id, alias)?.is_none() {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    json_response(200, json!({"enabled": false}))
}

fn update_identity_provider_permissions(
    conn: &Connection,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_identity_provider_by_alias(conn, &realm_id, alias)?.is_none() {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    json_response(200, value)
}

fn list_identity_provider_mapper_types(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_identity_provider_by_alias(conn, &realm_id, alias)?.is_none() {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_identity_provider_mappers(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_identity_provider_by_alias(conn, &realm_id, alias)?.is_none() {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    let rows = conn
        .execute(
            "SELECT ID FROM IDENTITY_PROVIDER_MAPPER WHERE REALM_ID=?1 AND IDP_ALIAS=?2 ORDER BY NAME",
            &[
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("list identity provider mappers")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(mapper_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(mapper) = load_identity_provider_mapper(conn, &realm_id, mapper_id)? {
            items.push(mapper);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_identity_provider_mapper(
    conn: &Connection,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_identity_provider_by_alias(conn, &realm_id, alias)?.is_none() {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return json_response(400, json!({"error": "name is required"})),
    };
    let mapper_type = match value.get("identityProviderMapper").and_then(|v| v.as_str()) {
        Some(mapper_type) => mapper_type.to_string(),
        None => return json_response(400, json!({"error": "identityProviderMapper is required"})),
    };
    let mapper_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("idp-mapper"));
    if identity_provider_mapper_exists(conn, &mapper_id)? {
        return json_response(409, json!({"error": "identity provider mapper already exists"}));
    }
    value["id"] = JsonValue::String(mapper_id.clone());
    value["identityProviderAlias"] = JsonValue::String(alias.to_string());
    value["name"] = JsonValue::String(name);
    value["identityProviderMapper"] = JsonValue::String(mapper_type);

    execute_transaction(conn, |conn| {
        insert_identity_provider_mapper(conn, &realm_id, alias, &mapper_id, &value)?;
        insert_identity_provider_mapper_config(conn, &mapper_id, &value)?;
        Ok(())
    })
    .context("insert identity provider mapper")?;

    let mapper = load_identity_provider_mapper(conn, &realm_id, &mapper_id)?
        .ok_or_else(|| anyhow!("identity provider mapper not found after create"))?;
    json_response(200, mapper)
}

fn get_identity_provider_mapper(
    conn: &Connection,
    realm: &str,
    alias: &str,
    mapper_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(mapper) = load_identity_provider_mapper(conn, &realm_id, mapper_id)? else {
        return json_response(404, json!({"error": "mapper not found"}));
    };
    if mapper
        .get("identityProviderAlias")
        .and_then(|v| v.as_str())
        != Some(alias)
    {
        return json_response(404, json!({"error": "mapper not found"}));
    }
    json_response(200, mapper)
}

fn update_identity_provider_mapper(
    conn: &Connection,
    realm: &str,
    alias: &str,
    mapper_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_identity_provider_mapper(conn, &realm_id, mapper_id)? {
        Some(mapper) => mapper,
        None => return json_response(404, json!({"error": "mapper not found"})),
    };
    if current
        .get("identityProviderAlias")
        .and_then(|v| v.as_str())
        != Some(alias)
    {
        return json_response(404, json!({"error": "mapper not found"}));
    }
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(mapper_id.to_string());
    current["identityProviderAlias"] = JsonValue::String(alias.to_string());

    execute_transaction(conn, |conn| {
        update_identity_provider_mapper_row(conn, &realm_id, mapper_id, &current)?;
        if has_key(&patch, "config") {
            delete_identity_provider_mapper_config(conn, mapper_id)?;
            insert_identity_provider_mapper_config(conn, mapper_id, &current)?;
        }
        Ok(())
    })
    .context("update identity provider mapper")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_identity_provider_mapper(
    conn: &Connection,
    realm: &str,
    alias: &str,
    mapper_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(mapper) = load_identity_provider_mapper(conn, &realm_id, mapper_id)? else {
        return json_response(404, json!({"error": "mapper not found"}));
    };
    if mapper
        .get("identityProviderAlias")
        .and_then(|v| v.as_str())
        != Some(alias)
    {
        return json_response(404, json!({"error": "mapper not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_identity_provider_mapper_config(conn, mapper_id)?;
        conn.execute(
            "DELETE FROM IDENTITY_PROVIDER_MAPPER WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(mapper_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("delete identity provider mapper")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_identity_provider_factory(
    conn: &Connection,
    realm: &str,
    provider_id: &str,
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, json!({"id": provider_id}))
}

fn list_components(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let name_filter = first_param(&params, "name");
    let parent_filter = first_param(&params, "parent");
    let type_filter = first_param(&params, "type");

    let mut sql = "SELECT ID FROM COMPONENT WHERE REALM_ID=?1".to_string();
    let mut values = vec![SqlValue::Text(realm_id.clone())];
    let mut index = 2;
    if let Some(name) = name_filter {
        sql.push_str(&format!(" AND NAME=?{index}"));
        values.push(SqlValue::Text(name));
        index += 1;
    }
    if let Some(parent) = parent_filter {
        sql.push_str(&format!(" AND PARENT_ID=?{index}"));
        values.push(SqlValue::Text(parent));
        index += 1;
    }
    if let Some(provider_type) = type_filter {
        sql.push_str(&format!(" AND PROVIDER_TYPE=?{index}"));
        values.push(SqlValue::Text(provider_type));
    }
    sql.push_str(" ORDER BY NAME");
    let rows = conn.execute(&sql, &values).context("list components")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(component_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(component) = load_component_by_id(conn, component_id)? {
            items.push(component);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_component(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let component_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("component"));

    if component_id_exists(conn, &component_id)? {
        return json_response(409, json!({"error": "component already exists"}));
    }
    value["id"] = JsonValue::String(component_id.clone());

    execute_transaction(conn, |conn| {
        insert_component(conn, &realm_id, &component_id, &value)?;
        insert_component_config(conn, &component_id, &value)?;
        Ok(())
    })
    .context("insert component")?;

    json_response(201, json!({"id": component_id}))
}

fn get_component(conn: &Connection, realm: &str, component_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(component) = load_component_by_id_in_realm(conn, &realm_id, component_id)? else {
        return json_response(404, json!({"error": "component not found"}));
    };
    json_response(200, component)
}

fn update_component(
    conn: &Connection,
    realm: &str,
    component_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_component_by_id_in_realm(conn, &realm_id, component_id)? {
        Some(component) => component,
        None => return json_response(404, json!({"error": "component not found"})),
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(component_id.to_string());

    execute_transaction(conn, |conn| {
        update_component_row(conn, &realm_id, component_id, &current)?;
        if has_key(&patch, "config") {
            delete_component_config(conn, component_id)?;
            insert_component_config(conn, component_id, &current)?;
        }
        Ok(())
    })
    .context("update component")?;

    json_response(200, current)
}

fn delete_component(conn: &Connection, realm: &str, component_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !component_in_realm(conn, &realm_id, component_id)? {
        return json_response(404, json!({"error": "component not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_component_config(conn, component_id)?;
        conn.execute(
            "DELETE FROM COMPONENT WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(component_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("delete component")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_component_subtypes(
    conn: &Connection,
    realm: &str,
    component_id: &str,
    _query: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !component_in_realm(conn, &realm_id, component_id)? {
        return json_response(404, json!({"error": "component not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn list_client_scopes(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT_SCOPE WHERE REALM_ID=?1 ORDER BY NAME",
            &[SqlValue::Text(realm_id.clone())],
        )
        .context("list client scopes")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(scope_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(scope) = load_client_scope_by_id(conn, &realm_id, scope_id)? {
            items.push(scope);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_client_scope(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return json_response(400, json!({"error": "name is required"})),
    };
    if client_scope_name_exists(conn, &realm_id, &name)? {
        return json_response(409, json!({"error": "client scope already exists"}));
    }
    let scope_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("scope"));
    if client_scope_id_exists(conn, &scope_id)? {
        return json_response(409, json!({"error": "client scope already exists"}));
    }
    value["id"] = JsonValue::String(scope_id.clone());
    value["name"] = JsonValue::String(name.clone());

    execute_transaction(conn, |conn| {
        insert_client_scope(conn, &realm_id, &scope_id, &name, &value)?;
        insert_client_scope_attributes(conn, &scope_id, &value)?;
        Ok(())
    })
    .context("insert client scope")?;

    json_response(201, json!({"status": "created"}))
}

fn get_client_scope(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(scope) = load_client_scope_by_id(conn, &realm_id, scope_id)? else {
        return json_response(404, json!({"error": "client scope not found"}));
    };
    json_response(200, scope)
}

fn update_client_scope(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_client_scope_by_id(conn, &realm_id, scope_id)? {
        Some(scope) => scope,
        None => return json_response(404, json!({"error": "client scope not found"})),
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(scope_id.to_string());

    if let Some(next_name) = patch.get("name").and_then(|v| v.as_str()) {
        let current_name = current.get("name").and_then(|v| v.as_str());
        if current_name != Some(next_name)
            && client_scope_name_exists(conn, &realm_id, next_name)?
        {
            return json_response(409, json!({"error": "client scope already exists"}));
        }
    }

    execute_transaction(conn, |conn| {
        update_client_scope_row(conn, &realm_id, scope_id, &current)?;
        if has_key(&patch, "attributes") {
            delete_client_scope_attributes(conn, scope_id)?;
            insert_client_scope_attributes(conn, scope_id, &current)?;
        }
        Ok(())
    })
    .context("update client scope")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_client_scope(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_client_scope_by_id(conn, &realm_id, scope_id)?.is_none() {
        return json_response(404, json!({"error": "client scope not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_client_scope_children(conn, scope_id)?;
        conn.execute(
            "DELETE FROM CLIENT_SCOPE WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(scope_id.to_string()), SqlValue::Text(realm_id)],
        )
        .context("delete client scope")?;
        Ok(())
    })?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn add_protocol_mappers(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    if body.is_empty() {
        return json_response(400, json!({"error": "request body is required"}));
    }
    let value: JsonValue = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let Some(items) = value.as_array() else {
        return json_response(400, json!({"error": "array is required"}));
    };
    execute_transaction(conn, |conn| {
        for item in items {
            insert_protocol_mapper(conn, scope_id, item)?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_protocol_mappers(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    protocol: Option<&str>,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let mut sql =
        "SELECT ID, NAME, PROTOCOL, PROTOCOL_MAPPER_NAME FROM PROTOCOL_MAPPER WHERE CLIENT_SCOPE_ID=?1".to_string();
    let mut params = vec![SqlValue::Text(scope_id.to_string())];
    if let Some(protocol) = protocol {
        sql.push_str(" AND PROTOCOL=?2");
        params.push(SqlValue::Text(protocol.to_string()));
    }
    sql.push_str(" ORDER BY NAME");
    let rows = conn.execute(&sql, &params).context("list protocol mappers")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(mapper_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(mapper) = load_protocol_mapper(conn, mapper_id)? {
            items.push(mapper);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn create_protocol_mapper(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    insert_protocol_mapper(conn, scope_id, &value)?;
    json_response(201, json!({"status": "created"}))
}

fn get_protocol_mapper(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    mapper_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let Some(mapper) = load_protocol_mapper(conn, mapper_id)? else {
        return json_response(404, json!({"error": "mapper not found"}));
    };
    json_response(200, mapper)
}

fn update_protocol_mapper(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    mapper_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_protocol_mapper(conn, mapper_id)? {
        Some(mapper) => mapper,
        None => return json_response(404, json!({"error": "mapper not found"})),
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(mapper_id.to_string());

    execute_transaction(conn, |conn| {
        update_protocol_mapper_row(conn, mapper_id, scope_id, &current)?;
        if has_key(&patch, "config") {
            delete_protocol_mapper_config(conn, mapper_id)?;
            insert_protocol_mapper_config(conn, mapper_id, &current)?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_protocol_mapper(
    conn: &Connection,
    realm: &str,
    scope_id: &str,
    mapper_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    if load_protocol_mapper(conn, mapper_id)?.is_none() {
        return json_response(404, json!({"error": "mapper not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_protocol_mapper_config(conn, mapper_id)?;
        conn.execute(
            "DELETE FROM PROTOCOL_MAPPER WHERE ID=?1 AND CLIENT_SCOPE_ID=?2",
            &[SqlValue::Text(mapper_id.to_string()), SqlValue::Text(scope_id.to_string())],
        )
        .context("delete protocol mapper")?;
        Ok(())
    })?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_scope_mappings(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn list_scope_mapping_client(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    json_response(200, JsonValue::Array(Vec::new()))
}

fn update_scope_mapping_client(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_scope_mapping_realm(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    json_response(200, JsonValue::Array(Vec::new()))
}

fn update_scope_mapping_realm(conn: &Connection, realm: &str, scope_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    ensure_client_scope(conn, &realm_id, scope_id)?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn create_realm(conn: &Connection, body: &[u8]) -> Result<Response> {
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let realm = match value.get("realm").and_then(|v| v.as_str()) {
        Some(realm) => realm.to_string(),
        None => return json_response(400, json!({"error": "realm is required"})),
    };

    if realm_exists(conn, &realm)? {
        return json_response(409, json!({"error": "realm already exists"}));
    }

    if value.get("id").and_then(|v| v.as_str()).is_none() {
        value["id"] = JsonValue::String(realm.clone());
    }

    let realm_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&realm)
        .to_string();

    execute_transaction(conn, |conn| {
        insert_realm(conn, &realm_id, &realm, &value)?;
        insert_realm_children(conn, &realm_id, &value)?;
        Ok(())
    })
    .context("insert realm")?;

    json_response(201, json!({"status": "created"}))
}

fn get_realm(conn: &Connection, realm: &str) -> Result<Response> {
    if let Some(realm_id) = realm_id_by_name(conn, realm)? {
        let value = load_realm(conn, &realm_id, realm)?;
        return json_response(200, value);
    }

    json_response(404, json!({"error": "realm not found"}))
}

fn update_realm(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(existing_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };

    let mut patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    patch["realm"] = JsonValue::String(realm.to_string());
    if patch.get("id").and_then(|v| v.as_str()).is_none() {
        patch["id"] = JsonValue::String(existing_id.clone());
    }

    let requested_id = patch
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&existing_id);
    if requested_id != existing_id {
        return json_response(409, json!({"error": "realm id cannot be changed"}));
    }

    let mut merged = load_realm(conn, &existing_id, realm)?;
    merge_json(&mut merged, &patch);

    execute_transaction(conn, |conn| {
        update_realm_row(conn, &existing_id, realm, &merged)?;
        update_realm_children(conn, &existing_id, &patch, &merged)?;
        Ok(())
    })
    .context("update realm")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_realm(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    execute_transaction(conn, |conn| {
        delete_realm_children(conn, &realm_id)?;
        conn.execute(
            "DELETE FROM REALM WHERE ID=?1",
            &[SqlValue::Text(realm_id.to_string())],
        )
            .context("delete realm")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn parse_body(body: &[u8]) -> Result<JsonValue> {
    if body.is_empty() {
        return Err(anyhow!("request body is required"));
    }
    let value: JsonValue = serde_json::from_slice(body).context("parse request body")?;
    if !value.is_object() {
        return Err(anyhow!("request body must be an object"));
    }
    Ok(value)
}

fn parse_body_array(body: &[u8]) -> Result<Vec<JsonValue>> {
    if body.is_empty() {
        return Err(anyhow!("request body is required"));
    }
    let value: JsonValue = serde_json::from_slice(body).context("parse request body")?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("request body must be an array"))
}

fn parse_optional_object(body: &[u8]) -> Result<Option<JsonValue>> {
    if body.is_empty() {
        return Ok(None);
    }
    let value: JsonValue = serde_json::from_slice(body).context("parse request body")?;
    if !value.is_object() {
        return Err(anyhow!("request body must be an object"));
    }
    Ok(Some(value))
}

fn parse_identity_provider_reference(body: &[u8]) -> Result<String> {
    if body.is_empty() {
        return Err(anyhow!("request body is required"));
    }
    let value: JsonValue = serde_json::from_slice(body).context("parse request body")?;
    match value {
        JsonValue::String(alias) => Ok(alias),
        JsonValue::Object(map) => {
            if let Some(alias) = map.get("alias").and_then(|v| v.as_str()) {
                return Ok(alias.to_string());
            }
            if let Some(id) = map
                .get("id")
                .or_else(|| map.get("internalId"))
                .and_then(|v| v.as_str())
            {
                return Ok(id.to_string());
            }
            Err(anyhow!("id or alias is required"))
        }
        _ => Err(anyhow!("request body must be a string or object")),
    }
}

fn split_realm_path(path: &str) -> Option<(&str, &str)> {
    let tail = path.strip_prefix("/admin/realms/")?;
    let mut iter = tail.splitn(2, '/');
    let realm = iter.next().unwrap_or("");
    if realm.is_empty() {
        return None;
    }
    let rest = iter.next().unwrap_or("");
    Some((realm, rest))
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    let rows = conn
        .execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='REALM'",
            &[],
        )
        .context("check REALM table")?;
    for row in rows.rows() {
        if row.get::<&str>("name").is_some() {
            return Ok(());
        }
    }
    Err(anyhow!("REALM table is missing; run /db/init first"))
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut iter = pair.splitn(2, '=');
        let name = iter.next().unwrap_or("");
        let value = iter.next().unwrap_or("");
        if name == key {
            return Some(value.to_string());
        }
    }
    None
}

fn json_response(status: u16, value: JsonValue) -> Result<Response> {
    let body = serde_json::to_vec(&value).context("serialize json response")?;
    let mut builder = Response::builder();
    Ok(builder
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(body)
        .build())
}

fn method_not_allowed() -> Result<Response> {
    let mut builder = Response::builder();
    Ok(builder.status(405).body(Vec::new()).build())
}

fn load_schema_version(conn: &Connection) -> Result<Option<String>> {
    let rows = conn
        .execute("SELECT version FROM kc_schema_version WHERE id=1", &[])
        .context("read schema version")?;
    for row in rows.rows() {
        if let Some(version) = row.get::<&str>("version") {
            return Ok(Some(version.to_string()));
        }
    }
    Ok(None)
}

fn list_events(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);

    let mut sql = String::from(
        "SELECT ID, EVENT_TIME, TYPE, REALM_ID, CLIENT_ID, USER_ID, SESSION_ID, IP_ADDRESS, ERROR, DETAILS_JSON, DETAILS_JSON_LONG_VALUE FROM EVENT_ENTITY WHERE REALM_ID=?1",
    );
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];

    if let Some(client) = first_param(&params, "client") {
        sql.push_str(&format!(" AND CLIENT_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(client));
    }
    if let Some(user) = first_param(&params, "user") {
        sql.push_str(&format!(" AND USER_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(user));
    }
    if let Some(ip) = first_param(&params, "ipAddress") {
        sql.push_str(&format!(" AND IP_ADDRESS=?{}", values.len() + 1));
        values.push(SqlValue::Text(ip));
    }
    if let Some(from) = parse_epoch_millis(&params, "dateFrom") {
        sql.push_str(&format!(" AND EVENT_TIME>=?{}", values.len() + 1));
        values.push(SqlValue::Integer(from));
    }
    if let Some(to) = parse_epoch_millis(&params, "dateTo") {
        sql.push_str(&format!(" AND EVENT_TIME<=?{}", values.len() + 1));
        values.push(SqlValue::Integer(to));
    }
    let types = list_param(&params, "type");
    if !types.is_empty() {
        let mut placeholders = Vec::new();
        for value in types {
            placeholders.push(format!("?{}", values.len() + 1));
            values.push(SqlValue::Text(value));
        }
        sql.push_str(&format!(" AND TYPE IN ({})", placeholders.join(",")));
    }

    let direction = first_param(&params, "direction")
        .unwrap_or_else(|| "desc".to_string());
    let direction = if direction.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    };
    sql.push_str(&format!(" ORDER BY EVENT_TIME {direction}"));

    let max = int_param(&params, "max").unwrap_or(100).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);
    sql.push_str(&format!(" LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list events")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut event = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut event, "id", row.get::<&str>("ID"));
        set_opt_int(&mut event, "time", row.get::<i64>("EVENT_TIME"));
        set_opt_string(&mut event, "type", row.get::<&str>("TYPE"));
        set_opt_string(&mut event, "realmId", row.get::<&str>("REALM_ID"));
        set_opt_string(&mut event, "clientId", row.get::<&str>("CLIENT_ID"));
        set_opt_string(&mut event, "userId", row.get::<&str>("USER_ID"));
        set_opt_string(&mut event, "sessionId", row.get::<&str>("SESSION_ID"));
        set_opt_string(&mut event, "ipAddress", row.get::<&str>("IP_ADDRESS"));
        set_opt_string(&mut event, "error", row.get::<&str>("ERROR"));

        let details = parse_details(
            row.get::<&str>("DETAILS_JSON")
                .or_else(|| row.get::<&str>("DETAILS_JSON_LONG_VALUE")),
        );
        if let Some(details) = details {
            event["details"] = details;
        }
        items.push(event);
    }

    json_response(200, JsonValue::Array(items))
}

fn delete_events(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    conn.execute(
        "DELETE FROM EVENT_ENTITY WHERE REALM_ID=?1",
        &[SqlValue::Text(realm_id)],
    )
    .context("delete events")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_admin_events(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);

    let mut sql = String::from(
        "SELECT ID, ADMIN_EVENT_TIME, REALM_ID, AUTH_REALM_ID, AUTH_CLIENT_ID, AUTH_USER_ID, IP_ADDRESS, OPERATION_TYPE, RESOURCE_TYPE, RESOURCE_PATH, REPRESENTATION, ERROR, DETAILS_JSON FROM ADMIN_EVENT_ENTITY WHERE REALM_ID=?1",
    );
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];

    if let Some(client) = first_param(&params, "authClient") {
        sql.push_str(&format!(" AND AUTH_CLIENT_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(client));
    }
    if let Some(user) = first_param(&params, "authUser") {
        sql.push_str(&format!(" AND AUTH_USER_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(user));
    }
    if let Some(auth_realm) = first_param(&params, "authRealm") {
        sql.push_str(&format!(" AND AUTH_REALM_ID=?{}", values.len() + 1));
        values.push(SqlValue::Text(auth_realm));
    }
    if let Some(ip) = first_param(&params, "authIpAddress") {
        sql.push_str(&format!(" AND IP_ADDRESS=?{}", values.len() + 1));
        values.push(SqlValue::Text(ip));
    }
    if let Some(path) = first_param(&params, "resourcePath") {
        sql.push_str(&format!(" AND RESOURCE_PATH=?{}", values.len() + 1));
        values.push(SqlValue::Text(path));
    }
    if let Some(from) = parse_epoch_millis(&params, "dateFrom") {
        sql.push_str(&format!(" AND ADMIN_EVENT_TIME>=?{}", values.len() + 1));
        values.push(SqlValue::Integer(from));
    }
    if let Some(to) = parse_epoch_millis(&params, "dateTo") {
        sql.push_str(&format!(" AND ADMIN_EVENT_TIME<=?{}", values.len() + 1));
        values.push(SqlValue::Integer(to));
    }

    let op_types = list_param(&params, "operationTypes");
    if !op_types.is_empty() {
        let mut placeholders = Vec::new();
        for value in op_types {
            placeholders.push(format!("?{}", values.len() + 1));
            values.push(SqlValue::Text(value));
        }
        sql.push_str(&format!(" AND OPERATION_TYPE IN ({})", placeholders.join(",")));
    }
    let resource_types = list_param(&params, "resourceTypes");
    if !resource_types.is_empty() {
        let mut placeholders = Vec::new();
        for value in resource_types {
            placeholders.push(format!("?{}", values.len() + 1));
            values.push(SqlValue::Text(value));
        }
        sql.push_str(&format!(" AND RESOURCE_TYPE IN ({})", placeholders.join(",")));
    }

    let direction = first_param(&params, "direction")
        .unwrap_or_else(|| "desc".to_string());
    let direction = if direction.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    };
    sql.push_str(&format!(" ORDER BY ADMIN_EVENT_TIME {direction}"));

    let max = int_param(&params, "max").unwrap_or(100).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);
    sql.push_str(&format!(" LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list admin events")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut event = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut event, "id", row.get::<&str>("ID"));
        set_opt_int(&mut event, "time", row.get::<i64>("ADMIN_EVENT_TIME"));
        set_opt_string(&mut event, "realmId", row.get::<&str>("REALM_ID"));
        set_opt_string(&mut event, "operationType", row.get::<&str>("OPERATION_TYPE"));
        set_opt_string(&mut event, "resourceType", row.get::<&str>("RESOURCE_TYPE"));
        set_opt_string(&mut event, "resourcePath", row.get::<&str>("RESOURCE_PATH"));
        set_opt_string(&mut event, "representation", row.get::<&str>("REPRESENTATION"));
        set_opt_string(&mut event, "error", row.get::<&str>("ERROR"));

        let mut auth = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut auth, "realmId", row.get::<&str>("AUTH_REALM_ID"));
        set_opt_string(&mut auth, "clientId", row.get::<&str>("AUTH_CLIENT_ID"));
        set_opt_string(&mut auth, "userId", row.get::<&str>("AUTH_USER_ID"));
        set_opt_string(&mut auth, "ipAddress", row.get::<&str>("IP_ADDRESS"));
        if auth.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
            event["authDetails"] = auth;
        }

        if let Some(details) = parse_details(row.get::<&str>("DETAILS_JSON")) {
            event["details"] = details;
        }
        items.push(event);
    }

    json_response(200, JsonValue::Array(items))
}

fn delete_admin_events(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    conn.execute(
        "DELETE FROM ADMIN_EVENT_ENTITY WHERE REALM_ID=?1",
        &[SqlValue::Text(realm_id)],
    )
    .context("delete admin events")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_events_config(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let config = load_events_config(conn, &realm_id)?;
    json_response(200, config)
}

fn update_events_config(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut merged = load_events_config(conn, &realm_id)?;
    merge_json(&mut merged, &patch);

    execute_transaction(conn, |conn| {
        conn.execute(
            "UPDATE REALM SET EVENTS_ENABLED=?1, EVENTS_EXPIRATION=?2, ADMIN_EVENTS_ENABLED=?3, ADMIN_EVENTS_DETAILS_ENABLED=?4 WHERE ID=?5",
            &[
                bool_value(&merged, "eventsEnabled"),
                int_value(&merged, "eventsExpiration"),
                bool_value(&merged, "adminEventsEnabled"),
                bool_value(&merged, "adminEventsDetailsEnabled"),
                SqlValue::Text(realm_id.clone()),
            ],
        )
        .context("update events config")?;

        if has_key(&patch, "eventsListeners") {
            delete_realm_child_table(conn, &realm_id, "REALM_EVENTS_LISTENERS")?;
            insert_realm_events_listeners(conn, &realm_id, &merged)?;
        }
        if has_key(&patch, "enabledEventTypes") {
            delete_realm_child_table(conn, &realm_id, "REALM_ENABLED_EVENT_TYPES")?;
            insert_realm_enabled_event_types(conn, &realm_id, &merged)?;
        }
        Ok(())
    })?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_keys(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let kid = format!("rsa-{realm}");
    let now_millis = current_epoch_seconds().saturating_mul(1000);
    let valid_to = now_millis.saturating_add(31_536_000_000);
    let response = json!({
        "active": {"RSA": kid.clone()},
        "keys": [
            {
                "providerId": "rsa",
                "providerPriority": 100,
                "kid": kid,
                "status": "ACTIVE",
                "type": "RSA",
                "algorithm": "RS256",
                "publicKey": "",
                "certificate": "",
                "use": "SIG",
                "validTo": valid_to
            }
        ]
    });
    json_response(200, response)
}

fn list_roles(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let mut sql = String::from("SELECT ID FROM KEYCLOAK_ROLE WHERE REALM_ID=?1");
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];

    if let Some(search) = first_param(&params, "search") {
        sql.push_str(&format!(" AND NAME LIKE ?{}", values.len() + 1));
        values.push(SqlValue::Text(format!("%{}%", search)));
    }
    sql.push_str(" ORDER BY NAME");

    let rows = conn.execute(&sql, &values).context("list roles")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(role_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(role) = load_role_by_id(conn, &realm_id, role_id)? {
            items.push(role);
        }
    }

    let first = int_param(&params, "first").unwrap_or(0).max(0) as usize;
    let max = int_param(&params, "max").unwrap_or(items.len() as i64).max(0) as usize;
    let sliced = items.into_iter().skip(first).take(max).collect::<Vec<_>>();
    json_response(200, JsonValue::Array(sliced))
}

fn create_role(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return json_response(400, json!({"error": "name is required"})),
    };
    if role_name_exists(conn, &realm_id, &name)? {
        return json_response(409, json!({"error": "role already exists"}));
    }
    let role_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("role"));
    if role_id_exists(conn, &role_id)? {
        return json_response(409, json!({"error": "role already exists"}));
    }

    execute_transaction(conn, |conn| {
        insert_role(conn, &realm_id, &role_id, &name, &value)?;
        insert_role_attributes(conn, &role_id, &value)?;
        Ok(())
    })
    .context("insert role")?;

    json_response(201, json!({"status": "created"}))
}

fn get_role(conn: &Connection, realm: &str, role_name: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role) = load_role_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    json_response(200, role)
}

fn update_role(conn: &Connection, realm: &str, role_name: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role_id) = role_id_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    update_role_by_id_inner(conn, &realm_id, &role_id, body)
}

fn delete_role(conn: &Connection, realm: &str, role_name: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role_id) = role_id_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    delete_role_by_id_inner(conn, &realm_id, &role_id)
}

fn get_role_by_id(conn: &Connection, realm: &str, role_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role) = load_role_by_id(conn, &realm_id, role_id)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    json_response(200, role)
}

fn update_role_by_id(conn: &Connection, realm: &str, role_id: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    update_role_by_id_inner(conn, &realm_id, role_id, body)
}

fn delete_role_by_id(conn: &Connection, realm: &str, role_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    delete_role_by_id_inner(conn, &realm_id, role_id)
}

fn get_role_by_id_permissions(
    conn: &Connection,
    realm: &str,
    role_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_role_by_id(conn, &realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    json_response(200, json!({"enabled": false}))
}

fn update_role_by_id_permissions(
    conn: &Connection,
    realm: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_role_by_id(conn, &realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    json_response(200, value)
}

fn list_role_composites(
    conn: &Connection,
    realm: &str,
    role_name: &str,
    scope: Option<&str>,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role_id) = role_id_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    list_role_by_id_composites(conn, realm, &role_id, scope)
}

fn add_role_composites(
    conn: &Connection,
    realm: &str,
    role_name: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role_id) = role_id_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    add_role_by_id_composites(conn, realm, &role_id, body)
}

fn delete_role_composites(
    conn: &Connection,
    realm: &str,
    role_name: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(role_id) = role_id_by_name(conn, &realm_id, role_name)? else {
        return json_response(404, json!({"error": "role not found"}));
    };
    delete_role_by_id_composites(conn, realm, &role_id, body)
}

fn list_role_by_id_composites(
    conn: &Connection,
    realm: &str,
    role_id: &str,
    scope: Option<&str>,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_role_by_id(conn, &realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    if matches!(scope, Some("clients")) {
        return json_response(200, JsonValue::Array(Vec::new()));
    }
    let rows = conn
        .execute(
            "SELECT CHILD_ROLE FROM COMPOSITE_ROLE WHERE COMPOSITE=?1",
            &[SqlValue::Text(role_id.to_string())],
        )
        .context("list composite roles")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(child_id) = row.get::<&str>("CHILD_ROLE") else {
            continue;
        };
        if let Some(role) = load_role_by_id(conn, &realm_id, child_id)? {
            items.push(role);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn add_role_by_id_composites(
    conn: &Connection,
    realm: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_role_by_id(conn, &realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    let items = match parse_body_array(body) {
        Ok(items) => items,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    execute_transaction(conn, |conn| {
        for item in items {
            let child_id = role_id_from_value(conn, &realm_id, &item)?;
            conn.execute(
                "INSERT OR IGNORE INTO COMPOSITE_ROLE (CHILD_ROLE, COMPOSITE) VALUES (?1, ?2)",
                &[
                    SqlValue::Text(child_id),
                    SqlValue::Text(role_id.to_string()),
                ],
            )
            .context("insert composite role")?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_role_by_id_composites(
    conn: &Connection,
    realm: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_role_by_id(conn, &realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    let items = match parse_body_array(body) {
        Ok(items) => items,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    execute_transaction(conn, |conn| {
        for item in items {
            let child_id = role_id_from_value(conn, &realm_id, &item)?;
            conn.execute(
                "DELETE FROM COMPOSITE_ROLE WHERE CHILD_ROLE=?1 AND COMPOSITE=?2",
                &[
                    SqlValue::Text(child_id),
                    SqlValue::Text(role_id.to_string()),
                ],
            )
            .context("delete composite role")?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_realm_session(conn: &Connection, realm: &str, _session_id: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_users(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let brief = first_param(&params, "briefRepresentation")
        .map(|v| v == "true")
        .unwrap_or(true);
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let search = first_param(&params, "search");
    let username = first_param(&params, "username");
    let email = first_param(&params, "email");
    let first_name = first_param(&params, "firstName");
    let last_name = first_param(&params, "lastName");

    let mut sql = "SELECT ID FROM USER_ENTITY WHERE REALM_ID=?1".to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];
    if let Some(term) = search {
        if exact {
            sql.push_str(&format!(
                " AND (USERNAME=?{} OR EMAIL=?{} OR FIRST_NAME=?{} OR LAST_NAME=?{})",
                values.len() + 1,
                values.len() + 2,
                values.len() + 3,
                values.len() + 4
            ));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(
                " AND (USERNAME LIKE ?{} OR EMAIL LIKE ?{} OR FIRST_NAME LIKE ?{} OR LAST_NAME LIKE ?{})",
                values.len() + 1,
                values.len() + 2,
                values.len() + 3,
                values.len() + 4
            ));
            let like = format!("%{term}%");
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like));
        }
    }
    if let Some(term) = username {
        if exact {
            sql.push_str(&format!(" AND USERNAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND USERNAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = email {
        if exact {
            sql.push_str(&format!(" AND EMAIL=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND EMAIL LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = first_name {
        if exact {
            sql.push_str(&format!(" AND FIRST_NAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND FIRST_NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = last_name {
        if exact {
            sql.push_str(&format!(" AND LAST_NAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND LAST_NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    sql.push_str(" ORDER BY USERNAME");

    let rows = conn.execute(&sql, &values).context("list users")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(user_id) = row.get::<&str>("ID") else {
            continue;
        };
        if let Some(mut user) = load_user_by_id(conn, &realm_id, user_id)? {
            if brief {
                if let Some(obj) = user.as_object_mut() {
                    obj.remove("attributes");
                    obj.remove("requiredActions");
                }
            }
            items.push(user);
        }
    }

    let first = int_param(&params, "first").unwrap_or(0).max(0) as usize;
    let max = int_param(&params, "max").unwrap_or(items.len() as i64).max(0) as usize;
    let sliced = items.into_iter().skip(first).take(max).collect::<Vec<_>>();
    json_response(200, JsonValue::Array(sliced))
}

fn count_users(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let search = first_param(&params, "search");
    let username = first_param(&params, "username");
    let email = first_param(&params, "email");
    let first_name = first_param(&params, "firstName");
    let last_name = first_param(&params, "lastName");

    let mut sql = "SELECT COUNT(*) AS CNT FROM USER_ENTITY WHERE REALM_ID=?1".to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id)];
    if let Some(term) = search {
        if exact {
            sql.push_str(&format!(
                " AND (USERNAME=?{} OR EMAIL=?{} OR FIRST_NAME=?{} OR LAST_NAME=?{})",
                values.len() + 1,
                values.len() + 2,
                values.len() + 3,
                values.len() + 4
            ));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(
                " AND (USERNAME LIKE ?{} OR EMAIL LIKE ?{} OR FIRST_NAME LIKE ?{} OR LAST_NAME LIKE ?{})",
                values.len() + 1,
                values.len() + 2,
                values.len() + 3,
                values.len() + 4
            ));
            let like = format!("%{term}%");
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like.clone()));
            values.push(SqlValue::Text(like));
        }
    }
    if let Some(term) = username {
        if exact {
            sql.push_str(&format!(" AND USERNAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND USERNAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = email {
        if exact {
            sql.push_str(&format!(" AND EMAIL=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND EMAIL LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = first_name {
        if exact {
            sql.push_str(&format!(" AND FIRST_NAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND FIRST_NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    if let Some(term) = last_name {
        if exact {
            sql.push_str(&format!(" AND LAST_NAME=?{}", values.len() + 1));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND LAST_NAME LIKE ?{}", values.len() + 1));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    let rows = conn.execute(&sql, &values).context("count users")?;
    let mut count = 0;
    if let Some(row) = rows.rows().next() {
        count = row.get::<i64>("CNT").unwrap_or(0);
    }
    json_response(200, json!({"count": count}))
}

fn create_user(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let username = match value.get("username").and_then(|v| v.as_str()) {
        Some(username) => username.to_string(),
        None => return json_response(400, json!({"error": "username is required"})),
    };
    if user_username_exists(conn, &realm_id, &username)? {
        return json_response(409, json!({"error": "user already exists"}));
    }
    let user_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("user"));
    if user_id_exists(conn, &user_id)? {
        return json_response(409, json!({"error": "user already exists"}));
    }
    if value.get("enabled").is_none() {
        value["enabled"] = JsonValue::Bool(true);
    }
    if value.get("emailVerified").is_none() {
        value["emailVerified"] = JsonValue::Bool(false);
    }
    if value.get("createdTimestamp").is_none() {
        let now = current_epoch_seconds().saturating_mul(1000);
        value["createdTimestamp"] = JsonValue::Number(now.into());
    }
    value["id"] = JsonValue::String(user_id.clone());
    value["username"] = JsonValue::String(username);

    execute_transaction(conn, |conn| {
        insert_user(conn, &realm_id, &user_id, &value)?;
        insert_user_attributes(conn, &user_id, &value)?;
        insert_user_required_actions(conn, &user_id, &value)?;
        Ok(())
    })
    .context("insert user")?;

    json_response(201, json!({"id": user_id}))
}

fn get_user(conn: &Connection, realm: &str, user_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(user) = load_user_by_id(conn, &realm_id, user_id)? else {
        return json_response(404, json!({"error": "user not found"}));
    };
    json_response(200, user)
}

fn update_user(conn: &Connection, realm: &str, user_id: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_user_by_id(conn, &realm_id, user_id)? {
        Some(user) => user,
        None => return json_response(404, json!({"error": "user not found"})),
    };
    if let Some(next_username) = patch.get("username").and_then(|v| v.as_str()) {
        if current.get("username").and_then(|v| v.as_str()) != Some(next_username)
            && user_username_exists(conn, &realm_id, next_username)?
        {
            return json_response(409, json!({"error": "user already exists"}));
        }
    }
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(user_id.to_string());

    execute_transaction(conn, |conn| {
        update_user_row(conn, &realm_id, user_id, &current)?;
        if has_key(&patch, "attributes") {
            delete_user_attributes(conn, user_id)?;
            insert_user_attributes(conn, user_id, &current)?;
        }
        if has_key(&patch, "requiredActions") {
            delete_user_required_actions(conn, user_id)?;
            insert_user_required_actions(conn, user_id, &current)?;
        }
        Ok(())
    })
    .context("update user")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_user(conn: &Connection, realm: &str, user_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_user_by_id(conn, &realm_id, user_id)?.is_none() {
        return json_response(404, json!({"error": "user not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_user_children(conn, user_id)?;
        conn.execute(
            "DELETE FROM USER_ENTITY WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(user_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("delete user")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_user_sessions(conn: &Connection, realm: &str, user_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_user_by_id(conn, &realm_id, user_id)?.is_none() {
        return json_response(404, json!({"error": "user not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn get_users_profile(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, json!({"attributes": []}))
}

fn update_users_profile(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    json_response(200, value)
}

fn get_users_profile_metadata(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, json!({"attributes": []}))
}

fn get_users_management_permissions(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, json!({"enabled": false}))
}

fn update_users_management_permissions(
    conn: &Connection,
    realm: &str,
    body: &[u8],
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    json_response(200, value)
}

fn list_workflows(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn get_workflow(conn: &Connection, realm: &str, workflow_id: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, json!({"id": workflow_id}))
}

fn list_workflow_scheduled(
    conn: &Connection,
    realm: &str,
    resource_id: &str,
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let rows = conn
        .execute(
            "SELECT EXECUTION_ID, RESOURCE_ID, RESOURCE_TYPE, SCHEDULED_STEP_ID, SCHEDULED_STEP_TIMESTAMP, WORKFLOW_ID FROM WORKFLOW_STATE WHERE RESOURCE_ID=?1",
            &[SqlValue::Text(resource_id.to_string())],
        )
        .context("list workflow scheduled")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut value = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut value, "executionId", row.get::<&str>("EXECUTION_ID"));
        set_opt_string(&mut value, "resourceId", row.get::<&str>("RESOURCE_ID"));
        set_opt_string(&mut value, "resourceType", row.get::<&str>("RESOURCE_TYPE"));
        set_opt_string(&mut value, "scheduledStepId", row.get::<&str>("SCHEDULED_STEP_ID"));
        set_opt_int(
            &mut value,
            "scheduledStepTimestamp",
            row.get::<i64>("SCHEDULED_STEP_TIMESTAMP"),
        );
        set_opt_string(&mut value, "workflowId", row.get::<&str>("WORKFLOW_ID"));
        items.push(value);
    }
    json_response(200, JsonValue::Array(items))
}

fn list_localizations(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT LOCALE FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1 ORDER BY LOCALE",
            &[SqlValue::Text(realm_id)],
        )
        .context("list localizations")?;
    let mut locales = Vec::new();
    for row in rows.rows() {
        if let Some(locale) = row.get::<&str>("LOCALE") {
            locales.push(JsonValue::String(locale.to_string()));
        }
    }
    json_response(200, JsonValue::Array(locales))
}

fn get_localization_locale(conn: &Connection, realm: &str, locale: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(texts) = load_localization_texts(conn, &realm_id, locale)? else {
        return json_response(404, json!({"error": "localization not found"}));
    };
    json_response(200, JsonValue::Object(texts))
}

fn import_localization_locale(
    conn: &Connection,
    realm: &str,
    locale: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    if !value.is_object() {
        return json_response(400, json!({"error": "request body must be an object"}));
    }
    execute_transaction(conn, |conn| {
        if localization_exists(conn, &realm_id, locale)? {
            conn.execute(
                "UPDATE REALM_LOCALIZATIONS SET TEXTS=?1 WHERE REALM_ID=?2 AND LOCALE=?3",
                &[
                    SqlValue::Text(json_to_string(&value)),
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                ],
            )
            .context("update localization")?;
        } else {
            conn.execute(
                "INSERT INTO REALM_LOCALIZATIONS (REALM_ID, LOCALE, TEXTS) VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                    SqlValue::Text(json_to_string(&value)),
                ],
            )
            .context("insert localization")?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_localization_locale(
    conn: &Connection,
    realm: &str,
    locale: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !localization_exists(conn, &realm_id, locale)? {
        return json_response(404, json!({"error": "localization not found"}));
    }
    conn.execute(
        "DELETE FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1 AND LOCALE=?2",
        &[
            SqlValue::Text(realm_id),
            SqlValue::Text(locale.to_string()),
        ],
    )
    .context("delete localization")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_localization_key(
    conn: &Connection,
    realm: &str,
    locale: &str,
    key: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(texts) = load_localization_texts(conn, &realm_id, locale)? else {
        return json_response(404, json!({"error": "localization not found"}));
    };
    let Some(value) = texts.get(key).and_then(|v| v.as_str()) else {
        return json_response(404, json!({"error": "localization key not found"}));
    };
    let mut builder = Response::builder();
    Ok(builder
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .body(value.as_bytes().to_vec())
        .build())
}

fn put_localization_key(
    conn: &Connection,
    realm: &str,
    locale: &str,
    key: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match std::str::from_utf8(body) {
        Ok(text) if !text.trim().is_empty() => text.to_string(),
        _ => return json_response(400, json!({"error": "request body is required"})),
    };
    let mut texts = load_localization_texts(conn, &realm_id, locale)?.unwrap_or_default();
    texts.insert(key.to_string(), JsonValue::String(value));
    let merged = JsonValue::Object(texts);
    execute_transaction(conn, |conn| {
        if localization_exists(conn, &realm_id, locale)? {
            conn.execute(
                "UPDATE REALM_LOCALIZATIONS SET TEXTS=?1 WHERE REALM_ID=?2 AND LOCALE=?3",
                &[
                    SqlValue::Text(json_to_string(&merged)),
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                ],
            )
            .context("update localization key")?;
        } else {
            conn.execute(
                "INSERT INTO REALM_LOCALIZATIONS (REALM_ID, LOCALE, TEXTS) VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                    SqlValue::Text(json_to_string(&merged)),
                ],
            )
            .context("insert localization key")?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_localization_key(
    conn: &Connection,
    realm: &str,
    locale: &str,
    key: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(mut texts) = load_localization_texts(conn, &realm_id, locale)? else {
        return json_response(404, json!({"error": "localization not found"}));
    };
    if texts.remove(key).is_none() {
        return json_response(404, json!({"error": "localization key not found"}));
    }
    execute_transaction(conn, |conn| {
        if texts.is_empty() {
            conn.execute(
                "DELETE FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1 AND LOCALE=?2",
                &[
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                ],
            )
            .context("delete localization")?;
        } else {
            let merged = JsonValue::Object(texts.clone());
            conn.execute(
                "UPDATE REALM_LOCALIZATIONS SET TEXTS=?1 WHERE REALM_ID=?2 AND LOCALE=?3",
                &[
                    SqlValue::Text(json_to_string(&merged)),
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(locale.to_string()),
                ],
            )
            .context("update localization")?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_organizations(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let brief = first_param(&params, "briefRepresentation")
        .map(|v| v == "true")
        .unwrap_or(true);
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let search = first_param(&params, "search");
    let max = int_param(&params, "max").unwrap_or(10).max(1);
    let first = int_param(&params, "first").unwrap_or(0).max(0);

    let mut sql = "SELECT ID, NAME, ALIAS, DESCRIPTION, ENABLED, GROUP_ID, REDIRECT_URL FROM ORG WHERE REALM_ID=?1".to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id.clone())];
    if let Some(term) = search {
        if exact {
            sql.push_str(&format!(" AND (NAME=?{} OR ALIAS=?{})", values.len() + 1, values.len() + 2));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND (NAME LIKE ?{} OR ALIAS LIKE ?{})", values.len() + 1, values.len() + 2));
            values.push(SqlValue::Text(format!("%{term}%")));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    sql.push_str(" ORDER BY NAME");
    sql.push_str(&format!(" LIMIT ?{} OFFSET ?{}", values.len() + 1, values.len() + 2));
    values.push(SqlValue::Integer(max));
    values.push(SqlValue::Integer(first));

    let rows = conn.execute(&sql, &values).context("list organizations")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut org = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut org, "id", row.get::<&str>("ID"));
        set_opt_string(&mut org, "name", row.get::<&str>("NAME"));
        set_opt_string(&mut org, "alias", row.get::<&str>("ALIAS"));
        if !brief {
            set_opt_string(&mut org, "description", row.get::<&str>("DESCRIPTION"));
            set_opt_bool(&mut org, "enabled", row.get::<i64>("ENABLED"));
            set_opt_string(&mut org, "groupId", row.get::<&str>("GROUP_ID"));
            set_opt_string(&mut org, "redirectUrl", row.get::<&str>("REDIRECT_URL"));
        }
        items.push(org);
    }
    json_response(200, JsonValue::Array(items))
}

fn count_organizations(conn: &Connection, realm: &str, query: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let params = parse_query_params(query);
    let exact = first_param(&params, "exact").map(|v| v == "true").unwrap_or(false);
    let search = first_param(&params, "search");
    let mut sql = "SELECT COUNT(*) AS CNT FROM ORG WHERE REALM_ID=?1".to_string();
    let mut values: Vec<SqlValue> = vec![SqlValue::Text(realm_id)];
    if let Some(term) = search {
        if exact {
            sql.push_str(&format!(" AND (NAME=?{} OR ALIAS=?{})", values.len() + 1, values.len() + 2));
            values.push(SqlValue::Text(term.to_string()));
            values.push(SqlValue::Text(term.to_string()));
        } else {
            sql.push_str(&format!(" AND (NAME LIKE ?{} OR ALIAS LIKE ?{})", values.len() + 1, values.len() + 2));
            values.push(SqlValue::Text(format!("%{term}%")));
            values.push(SqlValue::Text(format!("%{term}%")));
        }
    }
    let rows = conn.execute(&sql, &values).context("count organizations")?;
    let mut count = 0;
    if let Some(row) = rows.rows().next() {
        count = row.get::<i64>("CNT").unwrap_or(0);
    }
    json_response(200, json!({"count": count}))
}

fn create_organization(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return json_response(400, json!({"error": "name is required"})),
    };
    let alias = value
        .get("alias")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| name.clone());
    if organization_alias_exists(conn, &realm_id, &alias)? {
        return json_response(409, json!({"error": "organization already exists"}));
    }
    let org_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("org"));
    if organization_id_exists(conn, &realm_id, &org_id)? {
        return json_response(409, json!({"error": "organization already exists"}));
    }
    if value.get("enabled").is_none() {
        value["enabled"] = JsonValue::Bool(true);
    }
    value["id"] = JsonValue::String(org_id.clone());
    value["name"] = JsonValue::String(name);
    value["alias"] = JsonValue::String(alias);

    insert_organization(conn, &realm_id, &org_id, &value)?;
    json_response(201, json!({"id": org_id}))
}

fn get_organization(conn: &Connection, realm: &str, org_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(org) = load_organization_by_id(conn, &realm_id, org_id)? else {
        return json_response(404, json!({"error": "organization not found"}));
    };
    json_response(200, org)
}

fn update_organization(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let Some(mut current) = load_organization_by_id(conn, &realm_id, org_id)? else {
        return json_response(404, json!({"error": "organization not found"}));
    };
    merge_json(&mut current, &patch);
    current["id"] = JsonValue::String(org_id.to_string());
    update_organization_row(conn, &realm_id, org_id, &current)?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_organization(conn: &Connection, realm: &str, org_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    execute_transaction(conn, |conn| {
        conn.execute(
            "DELETE FROM ORG_DOMAIN WHERE ORG_ID=?1",
            &[SqlValue::Text(org_id.to_string())],
        )
        .context("delete org domains")?;
        conn.execute(
            "DELETE FROM ORG_INVITATION WHERE ORGANIZATION_ID=?1",
            &[SqlValue::Text(org_id.to_string())],
        )
        .context("delete org invitations")?;
        conn.execute(
            "UPDATE IDENTITY_PROVIDER SET ORGANIZATION_ID=NULL WHERE REALM_ID=?1 AND ORGANIZATION_ID=?2",
            &[
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(org_id.to_string()),
            ],
        )
        .context("clear org identity providers")?;
        conn.execute(
            "UPDATE KEYCLOAK_GROUP SET ORG_ID=NULL WHERE REALM_ID=?1 AND ORG_ID=?2",
            &[
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(org_id.to_string()),
            ],
        )
        .context("clear org groups")?;
        conn.execute(
            "DELETE FROM ORG WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(org_id.to_string()),
                SqlValue::Text(realm_id.clone()),
            ],
        )
        .context("delete org")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_organizations_for_member(
    conn: &Connection,
    realm: &str,
    _member_id: &str,
    _query: &str,
) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn list_organization_identity_providers(
    conn: &Connection,
    realm: &str,
    org_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    let rows = conn
        .execute(
            "SELECT PROVIDER_ALIAS FROM IDENTITY_PROVIDER WHERE REALM_ID=?1 AND ORGANIZATION_ID=?2 ORDER BY PROVIDER_ALIAS",
            &[
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(org_id.to_string()),
            ],
        )
        .context("list org identity providers")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let Some(alias) = row.get::<&str>("PROVIDER_ALIAS") else {
            continue;
        };
        if let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? {
            items.push(provider);
        }
    }
    json_response(200, JsonValue::Array(items))
}

fn add_organization_identity_provider(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    let reference = match parse_identity_provider_reference(body) {
        Ok(reference) => reference,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let (provider, internal_id) = if let Some(provider) =
        load_identity_provider_by_alias(conn, &realm_id, &reference)?
    {
        let internal_id = provider
            .get("internalId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (provider, internal_id)
    } else if let Some(provider) =
        load_identity_provider_by_internal_id(conn, &realm_id, &reference)?
    {
        (provider, reference)
    } else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    if provider
        .get("organizationId")
        .and_then(|v| v.as_str())
        .is_some()
    {
        return json_response(409, json!({"error": "identity provider already associated"}));
    }
    conn.execute(
        "UPDATE IDENTITY_PROVIDER SET ORGANIZATION_ID=?1 WHERE REALM_ID=?2 AND INTERNAL_ID=?3",
        &[
            SqlValue::Text(org_id.to_string()),
            SqlValue::Text(realm_id),
            SqlValue::Text(internal_id),
        ],
    )
    .context("associate identity provider")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_organization_identity_provider(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    alias: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    if provider
        .get("organizationId")
        .and_then(|v| v.as_str())
        != Some(org_id)
    {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    json_response(200, provider)
}

fn delete_organization_identity_provider(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    alias: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let Some(provider) = load_identity_provider_by_alias(conn, &realm_id, alias)? else {
        return json_response(404, json!({"error": "identity provider not found"}));
    };
    let organization_id = provider
        .get("organizationId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if organization_id != org_id {
        return json_response(404, json!({"error": "identity provider not found"}));
    }
    let internal_id = provider
        .get("internalId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    conn.execute(
        "UPDATE IDENTITY_PROVIDER SET ORGANIZATION_ID=NULL WHERE REALM_ID=?1 AND INTERNAL_ID=?2",
        &[
            SqlValue::Text(realm_id),
            SqlValue::Text(internal_id.to_string()),
        ],
    )
    .context("remove identity provider association")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_organization_invitations(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _query: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    let rows = conn
        .execute(
            "SELECT ID, EMAIL, FIRST_NAME, LAST_NAME, INVITE_LINK, CREATED_AT, EXPIRES_AT FROM ORG_INVITATION WHERE ORGANIZATION_ID=?1 ORDER BY CREATED_AT DESC",
            &[SqlValue::Text(org_id.to_string())],
        )
        .context("list organization invitations")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut item = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut item, "id", row.get::<&str>("ID"));
        set_opt_string(&mut item, "email", row.get::<&str>("EMAIL"));
        set_opt_string(&mut item, "firstName", row.get::<&str>("FIRST_NAME"));
        set_opt_string(&mut item, "lastName", row.get::<&str>("LAST_NAME"));
        set_opt_string(&mut item, "inviteLink", row.get::<&str>("INVITE_LINK"));
        set_opt_int(&mut item, "createdAt", row.get::<i64>("CREATED_AT"));
        set_opt_int(&mut item, "expiresAt", row.get::<i64>("EXPIRES_AT"));
        items.push(item);
    }
    json_response(200, JsonValue::Array(items))
}

fn get_organization_invitation(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    invitation_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    let Some(invitation) = load_organization_invitation(conn, org_id, invitation_id)? else {
        return json_response(404, json!({"error": "invitation not found"}));
    };
    json_response(200, invitation)
}

fn delete_organization_invitation(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    invitation_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    if load_organization_invitation(conn, org_id, invitation_id)?.is_none() {
        return json_response(404, json!({"error": "invitation not found"}));
    }
    conn.execute(
        "DELETE FROM ORG_INVITATION WHERE ORGANIZATION_ID=?1 AND ID=?2",
        &[
            SqlValue::Text(org_id.to_string()),
            SqlValue::Text(invitation_id.to_string()),
        ],
    )
    .context("delete invitation")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn resend_organization_invitation(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    invitation_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    if load_organization_invitation(conn, org_id, invitation_id)?.is_none() {
        return json_response(404, json!({"error": "invitation not found"}));
    }
    let now = current_epoch_seconds();
    conn.execute(
        "UPDATE ORG_INVITATION SET CREATED_AT=?1 WHERE ORGANIZATION_ID=?2 AND ID=?3",
        &[
            SqlValue::Integer(now),
            SqlValue::Text(org_id.to_string()),
            SqlValue::Text(invitation_id.to_string()),
        ],
    )
    .context("resend invitation")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_organization_members(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _query: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn add_organization_member(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(201).body(Vec::new()).build())
}

fn count_organization_members(
    conn: &Connection,
    realm: &str,
    org_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    json_response(200, json!({"count": 0}))
}

fn invite_existing_member(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    if let Some(value) = parse_optional_object(body)? {
        if let Some(email) = value.get("email").and_then(|v| v.as_str()) {
            create_organization_invitation(conn, org_id, email, &value)?;
        }
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn invite_member(conn: &Connection, realm: &str, org_id: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    if let Some(value) = parse_optional_object(body)? {
        if let Some(email) = value.get("email").and_then(|v| v.as_str()) {
            create_organization_invitation(conn, org_id, email, &value)?;
        }
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_organization_member(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _member_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    json_response(404, json!({"error": "member not found"}))
}

fn delete_organization_member(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _member_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    json_response(404, json!({"error": "member not found"}))
}

fn list_member_organizations(
    conn: &Connection,
    realm: &str,
    org_id: &str,
    _member_id: &str,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if load_organization_by_id(conn, &realm_id, org_id)?.is_none() {
        return json_response(404, json!({"error": "organization not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn list_auth_flows(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, DESCRIPTION, PROVIDER_ID, TOP_LEVEL, BUILT_IN FROM AUTHENTICATION_FLOW WHERE REALM_ID=?1 OR REALM_ID IS NULL ORDER BY ALIAS",
            &[SqlValue::Text(realm_id)],
        )
        .context("list auth flows")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut flow = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut flow, "id", row.get::<&str>("ID"));
        set_opt_string(&mut flow, "alias", row.get::<&str>("ALIAS"));
        set_opt_string(&mut flow, "description", row.get::<&str>("DESCRIPTION"));
        set_opt_string(&mut flow, "providerId", row.get::<&str>("PROVIDER_ID"));
        set_opt_bool(&mut flow, "topLevel", row.get::<i64>("TOP_LEVEL"));
        set_opt_bool(&mut flow, "builtIn", row.get::<i64>("BUILT_IN"));
        items.push(flow);
    }
    json_response(200, JsonValue::Array(items))
}

fn create_auth_flow(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let alias = match value.get("alias").and_then(|v| v.as_str()) {
        Some(alias) => alias.to_string(),
        None => return json_response(400, json!({"error": "alias is required"})),
    };
    let provider_id = match value.get("providerId").and_then(|v| v.as_str()) {
        Some(provider_id) => provider_id.to_string(),
        None => return json_response(400, json!({"error": "providerId is required"})),
    };
    if auth_flow_alias_exists(conn, &realm_id, &alias)? {
        return json_response(409, json!({"error": "flow alias already exists"}));
    }
    let id = value
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&alias)
        .to_string();
    if auth_flow_id_exists(conn, &id)? {
        return json_response(409, json!({"error": "flow id already exists"}));
    }

    conn.execute(
        "INSERT INTO AUTHENTICATION_FLOW (ID, REALM_ID, ALIAS, DESCRIPTION, PROVIDER_ID, TOP_LEVEL, BUILT_IN) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[
            SqlValue::Text(id),
            SqlValue::Text(realm_id),
            SqlValue::Text(alias),
            string_value(&value, "description"),
            SqlValue::Text(provider_id),
            bool_value(&value, "topLevel"),
            bool_value(&value, "builtIn"),
        ],
    )
    .context("insert auth flow")?;

    json_response(201, json!({"status": "created"}))
}

fn get_auth_flow(conn: &Connection, realm: &str, flow_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, DESCRIPTION, PROVIDER_ID, TOP_LEVEL, BUILT_IN FROM AUTHENTICATION_FLOW WHERE ID=?1 AND (REALM_ID=?2 OR REALM_ID IS NULL)",
            &[SqlValue::Text(flow_id.to_string()), SqlValue::Text(realm_id)],
        )
        .context("get auth flow")?;
    for row in rows.rows() {
        let mut flow = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut flow, "id", row.get::<&str>("ID"));
        set_opt_string(&mut flow, "alias", row.get::<&str>("ALIAS"));
        set_opt_string(&mut flow, "description", row.get::<&str>("DESCRIPTION"));
        set_opt_string(&mut flow, "providerId", row.get::<&str>("PROVIDER_ID"));
        set_opt_bool(&mut flow, "topLevel", row.get::<i64>("TOP_LEVEL"));
        set_opt_bool(&mut flow, "builtIn", row.get::<i64>("BUILT_IN"));
        return json_response(200, flow);
    }
    json_response(404, json!({"error": "flow not found"}))
}

fn update_auth_flow(
    conn: &Connection,
    realm: &str,
    flow_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let mut current = match load_auth_flow(conn, &realm_id, flow_id)? {
        Some(flow) => flow,
        None => return json_response(404, json!({"error": "flow not found"})),
    };
    merge_json(&mut current, &patch);

    conn.execute(
        "UPDATE AUTHENTICATION_FLOW SET ALIAS=?1, DESCRIPTION=?2, PROVIDER_ID=?3, TOP_LEVEL=?4, BUILT_IN=?5 WHERE ID=?6",
        &[
            string_value(&current, "alias"),
            string_value(&current, "description"),
            string_value(&current, "providerId"),
            bool_value(&current, "topLevel"),
            bool_value(&current, "builtIn"),
            SqlValue::Text(flow_id.to_string()),
        ],
    )
    .context("update auth flow")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_auth_flow(conn: &Connection, realm: &str, flow_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    execute_transaction(conn, |conn| {
        conn.execute(
            "DELETE FROM AUTHENTICATION_EXECUTION WHERE FLOW_ID=?1 OR AUTH_FLOW_ID=?1",
            &[SqlValue::Text(flow_id.to_string())],
        )
        .context("delete auth executions")?;
        conn.execute(
            "DELETE FROM AUTHENTICATION_FLOW WHERE ID=?1 AND (REALM_ID=?2 OR REALM_ID IS NULL)",
            &[SqlValue::Text(flow_id.to_string()), SqlValue::Text(realm_id)],
        )
        .context("delete auth flow")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_auth_flow_executions(
    conn: &Connection,
    realm: &str,
    flow_alias: &str,
) -> Result<Response> {
    let flow_id = match auth_flow_id_by_alias(conn, realm, flow_alias)? {
        Some(flow_id) => flow_id,
        None => return json_response(404, json!({"error": "flow not found"})),
    };
    let rows = conn
        .execute(
            "SELECT ID, REQUIREMENT, AUTHENTICATOR_FLOW, AUTHENTICATOR, AUTH_CONFIG, FLOW_ID, PRIORITY FROM AUTHENTICATION_EXECUTION WHERE FLOW_ID=?1 ORDER BY PRIORITY",
            &[SqlValue::Text(flow_id)],
        )
        .context("list auth executions")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut exec = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut exec, "id", row.get::<&str>("ID"));
        set_opt_string(&mut exec, "requirement", requirement_name(row.get::<i64>("REQUIREMENT")));
        set_opt_bool(&mut exec, "authenticationFlow", row.get::<i64>("AUTHENTICATOR_FLOW"));
        set_opt_string(&mut exec, "providerId", row.get::<&str>("AUTHENTICATOR"));
        set_opt_string(&mut exec, "authenticationConfig", row.get::<&str>("AUTH_CONFIG"));
        set_opt_string(&mut exec, "flowId", row.get::<&str>("FLOW_ID"));
        set_opt_int(&mut exec, "priority", row.get::<i64>("PRIORITY"));
        set_opt_int(&mut exec, "index", row.get::<i64>("PRIORITY"));
        items.push(exec);
    }
    json_response(200, JsonValue::Array(items))
}

fn update_auth_flow_execution(
    conn: &Connection,
    realm: &str,
    flow_alias: &str,
    body: &[u8],
) -> Result<Response> {
    let flow_id = match auth_flow_id_by_alias(conn, realm, flow_alias)? {
        Some(flow_id) => flow_id,
        None => return json_response(404, json!({"error": "flow not found"})),
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let exec_id = match patch.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return json_response(400, json!({"error": "id is required"})),
    };
    let mut current = match load_auth_execution(conn, &exec_id, &flow_id)? {
        Some(exec) => exec,
        None => return json_response(404, json!({"error": "execution not found"})),
    };
    merge_json(&mut current, &patch);

    let requirement = requirement_to_int(current.get("requirement").and_then(|v| v.as_str()));
    let priority = current.get("priority").and_then(|v| v.as_i64());
    let auth_config = current.get("authenticationConfig").and_then(|v| v.as_str());
    let auth_flow = current.get("authenticationFlow").and_then(|v| v.as_bool());

    conn.execute(
        "UPDATE AUTHENTICATION_EXECUTION SET REQUIREMENT=?1, PRIORITY=?2, AUTH_CONFIG=?3, AUTHENTICATOR_FLOW=?4 WHERE ID=?5 AND FLOW_ID=?6",
        &[
            requirement
                .map(SqlValue::Integer)
                .unwrap_or(SqlValue::Null),
            priority.map(SqlValue::Integer).unwrap_or(SqlValue::Null),
            auth_config
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null),
            auth_flow
                .map(|v| SqlValue::Integer(if v { 1 } else { 0 }))
                .unwrap_or(SqlValue::Null),
            SqlValue::Text(exec_id),
            SqlValue::Text(flow_id),
        ],
    )
    .context("update auth execution")?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_auth_providers(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn list_unregistered_required_actions(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Array(Vec::new()))
}

fn register_required_action(conn: &Connection, realm: &str, _body: &[u8]) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn list_required_actions(conn: &Connection, realm: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, NAME, PROVIDER_ID, ENABLED, DEFAULT_ACTION, PRIORITY FROM REQUIRED_ACTION_PROVIDER WHERE REALM_ID=?1 ORDER BY PRIORITY",
            &[SqlValue::Text(realm_id)],
        )
        .context("list required actions")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        let mut action = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut action, "alias", row.get::<&str>("ALIAS"));
        set_opt_string(&mut action, "name", row.get::<&str>("NAME"));
        set_opt_string(&mut action, "providerId", row.get::<&str>("PROVIDER_ID"));
        set_opt_bool(&mut action, "enabled", row.get::<i64>("ENABLED"));
        set_opt_bool(&mut action, "defaultAction", row.get::<i64>("DEFAULT_ACTION"));
        set_opt_int(&mut action, "priority", row.get::<i64>("PRIORITY"));
        let Some(action_id) = row.get::<&str>("ID") else {
            items.push(action);
            continue;
        };
        action["config"] = JsonValue::Object(load_required_action_config(conn, action_id)?);
        items.push(action);
    }
    json_response(200, JsonValue::Array(items))
}

fn get_required_action(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some(action) = load_required_action(conn, realm, alias)? else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    json_response(200, action)
}

fn update_required_action(
    conn: &Connection,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    let Some((realm_id, action_id, mut current)) = load_required_action_row(conn, realm, alias)?
    else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    let patch = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    merge_json(&mut current, &patch);
    current["alias"] = JsonValue::String(alias.to_string());

    conn.execute(
        "UPDATE REQUIRED_ACTION_PROVIDER SET ALIAS=?1, NAME=?2, PROVIDER_ID=?3, ENABLED=?4, DEFAULT_ACTION=?5, PRIORITY=?6 WHERE ID=?7 AND REALM_ID=?8",
        &[
            SqlValue::Text(alias.to_string()),
            string_value(&current, "name"),
            string_value(&current, "providerId"),
            bool_value(&current, "enabled"),
            bool_value(&current, "defaultAction"),
            int_value(&current, "priority"),
            SqlValue::Text(action_id.clone()),
            SqlValue::Text(realm_id),
        ],
    )
    .context("update required action")?;

    if has_key(&patch, "config") {
        delete_required_action_config_entries(conn, &action_id)?;
        if let Some(config_map) = current.get("config").and_then(|v| v.as_object()) {
            insert_required_action_config(conn, &action_id, config_map)?;
        }
    }

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_required_action(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some((realm_id, action_id, _)) = load_required_action_row(conn, realm, alias)? else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    execute_transaction(conn, |conn| {
        delete_required_action_config_entries(conn, &action_id)?;
        conn.execute(
            "DELETE FROM REQUIRED_ACTION_PROVIDER WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(action_id), SqlValue::Text(realm_id)],
        )
        .context("delete required action")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_required_action_config(conn: &Connection, realm: &str, alias: &str) -> Result<Response> {
    let Some((_realm_id, action_id, _)) = load_required_action_row(conn, realm, alias)? else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    let config = JsonValue::Object(load_required_action_config(conn, &action_id)?);
    json_response(200, json!({"config": config}))
}

fn update_required_action_config(
    conn: &Connection,
    realm: &str,
    alias: &str,
    body: &[u8],
) -> Result<Response> {
    let Some((_realm_id, action_id, _)) = load_required_action_row(conn, realm, alias)? else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let config = match value.get("config").and_then(|v| v.as_object()) {
        Some(config) => config,
        None => return json_response(400, json!({"error": "config is required"})),
    };
    execute_transaction(conn, |conn| {
        delete_required_action_config_entries(conn, &action_id)?;
        insert_required_action_config(conn, &action_id, config)?;
        Ok(())
    })?;

    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_required_action_config_endpoint(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    let Some((_realm_id, action_id, _)) = load_required_action_row(conn, realm, alias)? else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    delete_required_action_config_entries(conn, &action_id)?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_required_action_config_description(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Response> {
    if load_required_action_row(conn, realm, alias)?.is_none() {
        return json_response(404, json!({"error": "required action not found"}));
    }
    json_response(200, json!({"properties": []}))
}

fn update_required_action_priority(
    conn: &Connection,
    realm: &str,
    alias: &str,
    delta: i64,
) -> Result<Response> {
    let Some((realm_id, action_id, current)) = load_required_action_row(conn, realm, alias)?
    else {
        return json_response(404, json!({"error": "required action not found"}));
    };
    let current_priority = current.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
    let next_priority = (current_priority + delta).max(0);
    conn.execute(
        "UPDATE REQUIRED_ACTION_PROVIDER SET PRIORITY=?1 WHERE ID=?2 AND REALM_ID=?3",
        &[
            SqlValue::Integer(next_priority),
            SqlValue::Text(action_id),
            SqlValue::Text(realm_id),
        ],
    )
    .context("update required action priority")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn create_auth_execution(conn: &Connection, realm: &str, body: &[u8]) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let flow_id = match value.get("flowId").and_then(|v| v.as_str()) {
        Some(flow_id) => flow_id.to_string(),
        None => return json_response(400, json!({"error": "flowId is required"})),
    };
    let authenticator = match value.get("authenticator").and_then(|v| v.as_str()) {
        Some(authenticator) => authenticator.to_string(),
        None => return json_response(400, json!({"error": "authenticator is required"})),
    };
    let exec_id = match value.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return json_response(400, json!({"error": "id is required"})),
    };
    if auth_execution_exists(conn, &exec_id)? {
        return json_response(409, json!({"error": "execution already exists"}));
    }

    let requirement = requirement_to_int(value.get("requirement").and_then(|v| v.as_str()))
        .map(SqlValue::Integer)
        .unwrap_or(SqlValue::Null);
    let auth_flow = value
        .get("authenticatorFlow")
        .and_then(|v| v.as_bool())
        .map(|v| SqlValue::Integer(if v { 1 } else { 0 }))
        .unwrap_or(SqlValue::Null);
    let auth_config = value.get("authenticatorConfig").and_then(|v| v.as_str());
    let parent_flow = value.get("parentFlow").and_then(|v| v.as_str());

    let priority = value
        .get("priority")
        .and_then(|v| v.as_i64())
        .or_else(|| load_next_execution_priority(conn, &flow_id).ok());

    conn.execute(
        "INSERT INTO AUTHENTICATION_EXECUTION (ID, REALM_ID, FLOW_ID, AUTH_FLOW_ID, AUTHENTICATOR, AUTHENTICATOR_FLOW, REQUIREMENT, PRIORITY, AUTH_CONFIG) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        &[
            SqlValue::Text(exec_id),
            SqlValue::Text(realm_id),
            SqlValue::Text(flow_id),
            parent_flow
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null),
            SqlValue::Text(authenticator),
            auth_flow,
            requirement,
            priority.map(SqlValue::Integer).unwrap_or(SqlValue::Null),
            auth_config
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null),
        ],
    )
    .context("insert auth execution")?;

    json_response(201, json!({"status": "created"}))
}

fn get_auth_execution(conn: &Connection, realm: &str, exec_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT ID, AUTHENTICATOR, AUTHENTICATOR_FLOW, REQUIREMENT, PRIORITY, FLOW_ID, AUTH_FLOW_ID, AUTH_CONFIG FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(exec_id.to_string()), SqlValue::Text(realm_id)],
        )
        .context("get auth execution")?;
    for row in rows.rows() {
        let mut exec = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut exec, "id", row.get::<&str>("ID"));
        set_opt_string(&mut exec, "authenticator", row.get::<&str>("AUTHENTICATOR"));
        set_opt_bool(&mut exec, "authenticatorFlow", row.get::<i64>("AUTHENTICATOR_FLOW"));
        set_opt_string(&mut exec, "requirement", requirement_name(row.get::<i64>("REQUIREMENT")));
        set_opt_int(&mut exec, "priority", row.get::<i64>("PRIORITY"));
        set_opt_string(&mut exec, "flowId", row.get::<&str>("FLOW_ID"));
        set_opt_string(&mut exec, "parentFlow", row.get::<&str>("AUTH_FLOW_ID"));
        set_opt_string(&mut exec, "authenticatorConfig", row.get::<&str>("AUTH_CONFIG"));
        return json_response(200, exec);
    }
    json_response(404, json!({"error": "execution not found"}))
}

fn delete_auth_execution(conn: &Connection, realm: &str, exec_id: &str) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    conn.execute(
        "DELETE FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND REALM_ID=?2",
        &[SqlValue::Text(exec_id.to_string()), SqlValue::Text(realm_id)],
    )
    .context("delete auth execution")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn create_auth_execution_config(
    conn: &Connection,
    realm: &str,
    exec_id: &str,
    body: &[u8],
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !auth_execution_in_realm(conn, exec_id, &realm_id)? {
        return json_response(404, json!({"error": "execution not found"}));
    }
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    let config_id = match value.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return json_response(400, json!({"error": "id is required"})),
    };
    let alias = value.get("alias").and_then(|v| v.as_str()).unwrap_or("");
    if auth_config_exists(conn, &config_id)? {
        return json_response(409, json!({"error": "config already exists"}));
    }
    let config_map = value.get("config").and_then(|v| v.as_object());

    execute_transaction(conn, |conn| {
        conn.execute(
            "INSERT INTO AUTHENTICATOR_CONFIG (ID, REALM_ID, ALIAS) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(config_id.clone()),
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("insert auth config")?;
        if let Some(config_map) = config_map {
            insert_auth_config_entries(conn, &config_id, config_map)?;
        }
        conn.execute(
            "UPDATE AUTHENTICATION_EXECUTION SET AUTH_CONFIG=?1 WHERE ID=?2 AND REALM_ID=?3",
            &[
                SqlValue::Text(config_id.clone()),
                SqlValue::Text(exec_id.to_string()),
                SqlValue::Text(realm_id.clone()),
            ],
        )
        .context("attach auth config")?;
        Ok(())
    })?;

    json_response(201, json!({"status": "created"}))
}

fn get_auth_execution_config(
    conn: &Connection,
    realm: &str,
    exec_id: &str,
    config_id: Option<&str>,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    if !auth_execution_in_realm(conn, exec_id, &realm_id)? {
        return json_response(404, json!({"error": "execution not found"}));
    }
    let rows = conn
        .execute(
            "SELECT AUTH_CONFIG FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(exec_id.to_string()), SqlValue::Text(realm_id.clone())],
        )
        .context("load execution config id")?;
    let mut actual_id = None;
    for row in rows.rows() {
        actual_id = row.get::<&str>("AUTH_CONFIG").map(|v| v.to_string());
        break;
    }
    let Some(actual_id) = actual_id else {
        return json_response(404, json!({"error": "config not found"}));
    };
    if let Some(requested) = config_id {
        if requested != actual_id {
            return json_response(404, json!({"error": "config not found"}));
        }
    }
    let Some(config) = load_auth_config(conn, &actual_id)? else {
        return json_response(404, json!({"error": "config not found"}));
    };
    json_response(200, config)
}

fn update_auth_execution_priority(
    conn: &Connection,
    realm: &str,
    exec_id: &str,
    delta: i64,
) -> Result<Response> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return json_response(404, json!({"error": "realm not found"}));
    };
    let rows = conn
        .execute(
            "SELECT PRIORITY FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(exec_id.to_string()), SqlValue::Text(realm_id.clone())],
        )
        .context("load auth execution priority")?;
    let mut current_priority = None;
    for row in rows.rows() {
        current_priority = row.get::<i64>("PRIORITY");
        break;
    }
    let Some(current_priority) = current_priority else {
        return json_response(404, json!({"error": "execution not found"}));
    };
    let next_priority = (current_priority + delta).max(0);
    conn.execute(
        "UPDATE AUTHENTICATION_EXECUTION SET PRIORITY=?1 WHERE ID=?2 AND REALM_ID=?3",
        &[
            SqlValue::Integer(next_priority),
            SqlValue::Text(exec_id.to_string()),
            SqlValue::Text(realm_id),
        ],
    )
    .context("update auth execution priority")?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn clear_brute_force_all(conn: &Connection, realm: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn clear_brute_force_user(conn: &Connection, realm: &str, _user_id: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn get_brute_force_status(conn: &Connection, realm: &str, _user_id: &str) -> Result<Response> {
    if !realm_exists(conn, realm)? {
        return json_response(404, json!({"error": "realm not found"}));
    }
    json_response(200, JsonValue::Object(serde_json::Map::new()))
}

fn merge_json(target: &mut JsonValue, patch: &JsonValue) {
    let Some(target_map) = target.as_object_mut() else {
        return;
    };
    let Some(patch_map) = patch.as_object() else {
        return;
    };
    for (key, value) in patch_map {
        target_map.insert(key.clone(), value.clone());
    }
}

fn load_events_config(conn: &Connection, realm_id: &str) -> Result<JsonValue> {
    let rows = conn
        .execute(
            "SELECT EVENTS_ENABLED, EVENTS_EXPIRATION, ADMIN_EVENTS_ENABLED, ADMIN_EVENTS_DETAILS_ENABLED FROM REALM WHERE ID=?1",
            &[SqlValue::Text(realm_id.to_string())],
        )
        .context("load events config")?;
    let Some(row) = rows.rows().next() else {
        return Ok(json!({}));
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_bool(&mut value, "eventsEnabled", row.get::<i64>("EVENTS_ENABLED"));
    set_opt_int(&mut value, "eventsExpiration", row.get::<i64>("EVENTS_EXPIRATION"));
    set_opt_bool(
        &mut value,
        "adminEventsEnabled",
        row.get::<i64>("ADMIN_EVENTS_ENABLED"),
    );
    set_opt_bool(
        &mut value,
        "adminEventsDetailsEnabled",
        row.get::<i64>("ADMIN_EVENTS_DETAILS_ENABLED"),
    );
    value["eventsListeners"] =
        JsonValue::Array(load_values(conn, "REALM_EVENTS_LISTENERS", realm_id)?);
    value["enabledEventTypes"] =
        JsonValue::Array(load_values(conn, "REALM_ENABLED_EVENT_TYPES", realm_id)?);
    Ok(value)
}

fn parse_query_params(query: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut iter = pair.splitn(2, '=');
        let name = iter.next().unwrap_or("");
        let value = iter.next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        map.entry(name.to_string())
            .or_default()
            .push(value.to_string());
    }
    map
}

fn first_param(params: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    params.get(key).and_then(|values| values.first()).cloned()
}

fn list_param(params: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(items) = params.get(key) {
        for item in items {
            for value in item.split(',') {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    values.push(trimmed.to_string());
                }
            }
        }
    }
    values
}

fn int_param(params: &HashMap<String, Vec<String>>, key: &str) -> Option<i64> {
    first_param(params, key)?.parse::<i64>().ok()
}

fn parse_epoch_millis(params: &HashMap<String, Vec<String>>, key: &str) -> Option<i64> {
    let value = first_param(params, key)?;
    value.parse::<i64>().ok()
}

fn parse_details(value: Option<&str>) -> Option<JsonValue> {
    let raw = value?;
    let parsed = serde_json::from_str::<JsonValue>(raw).ok()?;
    if parsed.is_object() {
        Some(parsed)
    } else {
        None
    }
}

fn set_opt_string(target: &mut JsonValue, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        target[key] = JsonValue::String(value.to_string());
    }
}

fn set_opt_int(target: &mut JsonValue, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target[key] = JsonValue::Number(value.into());
    }
}

fn set_opt_bool(target: &mut JsonValue, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target[key] = JsonValue::Bool(value != 0);
    }
}

fn has_key(value: &JsonValue, key: &str) -> bool {
    value
        .as_object()
        .map(|obj| obj.contains_key(key))
        .unwrap_or(false)
}

fn realm_exists(conn: &Connection, realm: &str) -> Result<bool> {
    Ok(realm_id_by_name(conn, realm)?.is_some())
}

fn realm_id_by_name(conn: &Connection, realm: &str) -> Result<Option<String>> {
    let rows = conn
        .execute(
            "SELECT ID FROM REALM WHERE NAME=?1",
            &[SqlValue::Text(realm.to_string())],
        )
        .context("load realm id")?;
    for row in rows.rows() {
        if let Some(id) = row.get::<&str>("ID") {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

fn execute_transaction<F>(conn: &Connection, f: F) -> Result<()>
where
    F: FnOnce(&Connection) -> Result<()>,
{
    conn.execute("BEGIN", &[]).context("begin transaction")?;
    match f(conn) {
        Ok(()) => {
            conn.execute("COMMIT", &[]).context("commit transaction")?;
            Ok(())
        }
        Err(err) => {
            let _ = conn.execute("ROLLBACK", &[]);
            Err(err)
        }
    }
}

fn insert_realm(conn: &Connection, id: &str, name: &str, value: &JsonValue) -> Result<()> {
    conn.execute(
        "INSERT INTO REALM (ID, NAME, ENABLED, SSL_REQUIRED, REGISTRATION_ALLOWED, LOGIN_WITH_EMAIL_ALLOWED, DUPLICATE_EMAILS_ALLOWED, RESET_PASSWORD_ALLOWED, EDIT_USERNAME_ALLOWED, REMEMBER_ME, VERIFY_EMAIL, INTERNATIONALIZATION_ENABLED, DEFAULT_LOCALE, LOGIN_THEME, ACCOUNT_THEME, ADMIN_THEME, EMAIL_THEME, EVENTS_ENABLED, EVENTS_EXPIRATION, ADMIN_EVENTS_ENABLED, ADMIN_EVENTS_DETAILS_ENABLED, PASSWORD_POLICY, OTP_POLICY_ALG, OTP_POLICY_TYPE, OTP_POLICY_DIGITS, OTP_POLICY_PERIOD, OTP_POLICY_COUNTER, OTP_POLICY_WINDOW, ACCESS_TOKEN_LIFESPAN, SSO_IDLE_TIMEOUT, SSO_MAX_LIFESPAN, OFFLINE_SESSION_IDLE_TIMEOUT, ACCESS_CODE_LIFESPAN, LOGIN_LIFESPAN, USER_ACTION_LIFESPAN, NOT_BEFORE, REFRESH_TOKEN_MAX_REUSE, REVOKE_REFRESH_TOKEN, REG_EMAIL_AS_USERNAME, REGISTRATION_FLOW, RESET_CREDENTIALS_FLOW, BROWSER_FLOW, DIRECT_GRANT_FLOW, CLIENT_AUTH_FLOW, DOCKER_AUTH_FLOW, MASTER_ADMIN_CLIENT, DEFAULT_ROLE) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47)",
        &[
            SqlValue::Text(id.to_string()),
            SqlValue::Text(name.to_string()),
            bool_value(value, "enabled"),
            string_value(value, "sslRequired"),
            bool_value(value, "registrationAllowed"),
            bool_value(value, "loginWithEmailAllowed"),
            bool_value(value, "duplicateEmailsAllowed"),
            bool_value(value, "resetPasswordAllowed"),
            bool_value(value, "editUsernameAllowed"),
            bool_value(value, "rememberMe"),
            bool_value(value, "verifyEmail"),
            bool_value(value, "internationalizationEnabled"),
            string_value(value, "defaultLocale"),
            string_value(value, "loginTheme"),
            string_value(value, "accountTheme"),
            string_value(value, "adminTheme"),
            string_value(value, "emailTheme"),
            bool_value(value, "eventsEnabled"),
            int_value(value, "eventsExpiration"),
            bool_value(value, "adminEventsEnabled"),
            bool_value(value, "adminEventsDetailsEnabled"),
            string_value(value, "passwordPolicy"),
            string_value(value, "otpPolicyAlg"),
            string_value(value, "otpPolicyType"),
            int_value(value, "otpPolicyDigits"),
            int_value(value, "otpPolicyPeriod"),
            int_value(value, "otpPolicyCounter"),
            int_value(value, "otpPolicyWindow"),
            int_value(value, "accessTokenLifespan"),
            int_value(value, "ssoSessionIdleTimeout"),
            int_value(value, "ssoSessionMaxLifespan"),
            int_value(value, "offlineSessionIdleTimeout"),
            int_value(value, "accessCodeLifespan"),
            int_value(value, "loginLifespan"),
            int_value(value, "userActionLifespan"),
            int_value(value, "notBefore"),
            int_value(value, "refreshTokenMaxReuse"),
            bool_value(value, "revokeRefreshToken"),
            bool_value(value, "registrationEmailAsUsername"),
            string_value(value, "registrationFlow"),
            string_value(value, "resetCredentialsFlow"),
            string_value(value, "browserFlow"),
            string_value(value, "directGrantFlow"),
            string_value(value, "clientAuthenticationFlow"),
            string_value(value, "dockerAuthenticationFlow"),
            string_value(value, "masterAdminClient"),
            string_value(value, "defaultRole"),
        ],
    )
    .context("insert realm row")?;
    Ok(())
}

fn update_realm_row(conn: &Connection, id: &str, name: &str, value: &JsonValue) -> Result<()> {
    conn.execute(
        "UPDATE REALM SET NAME=?1, ENABLED=?2, SSL_REQUIRED=?3, REGISTRATION_ALLOWED=?4, LOGIN_WITH_EMAIL_ALLOWED=?5, DUPLICATE_EMAILS_ALLOWED=?6, RESET_PASSWORD_ALLOWED=?7, EDIT_USERNAME_ALLOWED=?8, REMEMBER_ME=?9, VERIFY_EMAIL=?10, INTERNATIONALIZATION_ENABLED=?11, DEFAULT_LOCALE=?12, LOGIN_THEME=?13, ACCOUNT_THEME=?14, ADMIN_THEME=?15, EMAIL_THEME=?16, EVENTS_ENABLED=?17, EVENTS_EXPIRATION=?18, ADMIN_EVENTS_ENABLED=?19, ADMIN_EVENTS_DETAILS_ENABLED=?20, PASSWORD_POLICY=?21, OTP_POLICY_ALG=?22, OTP_POLICY_TYPE=?23, OTP_POLICY_DIGITS=?24, OTP_POLICY_PERIOD=?25, OTP_POLICY_COUNTER=?26, OTP_POLICY_WINDOW=?27, ACCESS_TOKEN_LIFESPAN=?28, SSO_IDLE_TIMEOUT=?29, SSO_MAX_LIFESPAN=?30, OFFLINE_SESSION_IDLE_TIMEOUT=?31, ACCESS_CODE_LIFESPAN=?32, LOGIN_LIFESPAN=?33, USER_ACTION_LIFESPAN=?34, NOT_BEFORE=?35, REFRESH_TOKEN_MAX_REUSE=?36, REVOKE_REFRESH_TOKEN=?37, REG_EMAIL_AS_USERNAME=?38, REGISTRATION_FLOW=?39, RESET_CREDENTIALS_FLOW=?40, BROWSER_FLOW=?41, DIRECT_GRANT_FLOW=?42, CLIENT_AUTH_FLOW=?43, DOCKER_AUTH_FLOW=?44, MASTER_ADMIN_CLIENT=?45, DEFAULT_ROLE=?46 WHERE ID=?47",
        &[
            SqlValue::Text(name.to_string()),
            bool_value(value, "enabled"),
            string_value(value, "sslRequired"),
            bool_value(value, "registrationAllowed"),
            bool_value(value, "loginWithEmailAllowed"),
            bool_value(value, "duplicateEmailsAllowed"),
            bool_value(value, "resetPasswordAllowed"),
            bool_value(value, "editUsernameAllowed"),
            bool_value(value, "rememberMe"),
            bool_value(value, "verifyEmail"),
            bool_value(value, "internationalizationEnabled"),
            string_value(value, "defaultLocale"),
            string_value(value, "loginTheme"),
            string_value(value, "accountTheme"),
            string_value(value, "adminTheme"),
            string_value(value, "emailTheme"),
            bool_value(value, "eventsEnabled"),
            int_value(value, "eventsExpiration"),
            bool_value(value, "adminEventsEnabled"),
            bool_value(value, "adminEventsDetailsEnabled"),
            string_value(value, "passwordPolicy"),
            string_value(value, "otpPolicyAlg"),
            string_value(value, "otpPolicyType"),
            int_value(value, "otpPolicyDigits"),
            int_value(value, "otpPolicyPeriod"),
            int_value(value, "otpPolicyCounter"),
            int_value(value, "otpPolicyWindow"),
            int_value(value, "accessTokenLifespan"),
            int_value(value, "ssoSessionIdleTimeout"),
            int_value(value, "ssoSessionMaxLifespan"),
            int_value(value, "offlineSessionIdleTimeout"),
            int_value(value, "accessCodeLifespan"),
            int_value(value, "loginLifespan"),
            int_value(value, "userActionLifespan"),
            int_value(value, "notBefore"),
            int_value(value, "refreshTokenMaxReuse"),
            bool_value(value, "revokeRefreshToken"),
            bool_value(value, "registrationEmailAsUsername"),
            string_value(value, "registrationFlow"),
            string_value(value, "resetCredentialsFlow"),
            string_value(value, "browserFlow"),
            string_value(value, "directGrantFlow"),
            string_value(value, "clientAuthenticationFlow"),
            string_value(value, "dockerAuthenticationFlow"),
            string_value(value, "masterAdminClient"),
            string_value(value, "defaultRole"),
            SqlValue::Text(id.to_string()),
        ],
    )
    .context("update realm row")?;
    Ok(())
}

fn insert_realm_children(conn: &Connection, realm_id: &str, value: &JsonValue) -> Result<()> {
    insert_realm_attributes(conn, realm_id, value)?;
    insert_realm_smtp_config(conn, realm_id, value)?;
    insert_realm_supported_locales(conn, realm_id, value)?;
    insert_realm_events_listeners(conn, realm_id, value)?;
    insert_realm_enabled_event_types(conn, realm_id, value)?;
    insert_realm_default_groups(conn, realm_id, value)?;
    insert_realm_required_credentials(conn, realm_id, value)?;
    insert_realm_localizations(conn, realm_id, value)?;
    Ok(())
}

fn insert_realm_attributes(conn: &Connection, realm_id: &str, value: &JsonValue) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in attrs {
        let string_val = json_to_string(val);
        conn.execute(
            "INSERT INTO REALM_ATTRIBUTE (REALM_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(string_val),
            ],
        )
        .context("insert realm attribute")?;
    }
    Ok(())
}

fn insert_realm_smtp_config(conn: &Connection, realm_id: &str, value: &JsonValue) -> Result<()> {
    let Some(smtp) = value.get("smtpServer").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in smtp {
        conn.execute(
            "INSERT INTO REALM_SMTP_CONFIG (REALM_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert smtp config")?;
    }
    Ok(())
}

fn insert_realm_supported_locales(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("supportedLocales").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for locale in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO REALM_SUPPORTED_LOCALES (REALM_ID, VALUE) VALUES (?1, ?2)",
            &[SqlValue::Text(realm_id.to_string()), SqlValue::Text(locale.to_string())],
        )
        .context("insert supported locale")?;
    }
    Ok(())
}

fn insert_realm_events_listeners(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("eventsListeners").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for listener in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO REALM_EVENTS_LISTENERS (REALM_ID, VALUE) VALUES (?1, ?2)",
            &[SqlValue::Text(realm_id.to_string()), SqlValue::Text(listener.to_string())],
        )
        .context("insert events listener")?;
    }
    Ok(())
}

fn insert_realm_enabled_event_types(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("enabledEventTypes").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for event_type in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO REALM_ENABLED_EVENT_TYPES (REALM_ID, VALUE) VALUES (?1, ?2)",
            &[SqlValue::Text(realm_id.to_string()), SqlValue::Text(event_type.to_string())],
        )
        .context("insert enabled event type")?;
    }
    Ok(())
}

fn insert_realm_default_groups(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("defaultGroups").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for group in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO REALM_DEFAULT_GROUPS (REALM_ID, GROUP_ID) VALUES (?1, ?2)",
            &[SqlValue::Text(realm_id.to_string()), SqlValue::Text(group.to_string())],
        )
        .context("insert default group")?;
    }
    Ok(())
}

fn insert_realm_required_credentials(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("requiredCredentials").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for cred in values {
        let Some(obj) = cred.as_object() else {
            continue;
        };
        let Some(cred_type) = obj.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        conn.execute(
            "INSERT INTO REALM_REQUIRED_CREDENTIAL (INPUT, SECRET, REALM_ID, FORM_LABEL, TYPE) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                bool_value_map(obj, "input"),
                bool_value_map(obj, "secret"),
                SqlValue::Text(realm_id.to_string()),
                string_value_map(obj, "formLabel"),
                SqlValue::Text(cred_type.to_string()),
            ],
        )
        .context("insert required credential")?;
    }
    Ok(())
}

fn insert_realm_localizations(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let localization_source = value
        .get("localizationTexts")
        .or_else(|| value.get("localizations"));
    let Some(localizations) = localization_source.and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (locale, texts) in localizations {
        conn.execute(
            "INSERT INTO REALM_LOCALIZATIONS (REALM_ID, LOCALE, TEXTS) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(locale.to_string()),
                SqlValue::Text(json_to_string(texts)),
            ],
        )
        .context("insert localization")?;
    }
    Ok(())
}

fn delete_realm_children(conn: &Connection, realm_id: &str) -> Result<()> {
    let tables = [
        "REALM_ATTRIBUTE",
        "REALM_SMTP_CONFIG",
        "REALM_SUPPORTED_LOCALES",
        "REALM_EVENTS_LISTENERS",
        "REALM_ENABLED_EVENT_TYPES",
        "REALM_DEFAULT_GROUPS",
        "REALM_REQUIRED_CREDENTIAL",
        "REALM_LOCALIZATIONS",
    ];
    for table in tables {
        conn.execute(
            &format!("DELETE FROM {table} WHERE REALM_ID=?1"),
            &[SqlValue::Text(realm_id.to_string())],
        )
        .with_context(|| format!("delete realm children in {table}"))?;
    }
    Ok(())
}

fn insert_client(
    conn: &Connection,
    realm_id: &str,
    client_uuid: &str,
    client_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO CLIENT (ALWAYS_DISPLAY_IN_CONSOLE, BEARER_ONLY, CONSENT_REQUIRED, DIRECT_ACCESS_GRANTS_ENABLED, ENABLED, FRONTCHANNEL_LOGOUT, FULL_SCOPE_ALLOWED, IMPLICIT_FLOW_ENABLED, NODE_REREG_TIMEOUT, NOT_BEFORE, PUBLIC_CLIENT, SERVICE_ACCOUNTS_ENABLED, STANDARD_FLOW_ENABLED, SURROGATE_AUTH_REQUIRED, ID, BASE_URL, CLIENT_AUTHENTICATOR_TYPE, CLIENT_ID, DESCRIPTION, MANAGEMENT_URL, NAME, PROTOCOL, REALM_ID, REGISTRATION_TOKEN, ROOT_URL, SECRET) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
        &[
            bool_value(value, "alwaysDisplayInConsole"),
            bool_value(value, "bearerOnly"),
            bool_value(value, "consentRequired"),
            bool_value(value, "directAccessGrantsEnabled"),
            bool_value(value, "enabled"),
            bool_value(value, "frontchannelLogout"),
            bool_value(value, "fullScopeAllowed"),
            bool_value(value, "implicitFlowEnabled"),
            int_value(value, "nodeReRegistrationTimeout"),
            int_value(value, "notBefore"),
            bool_value(value, "publicClient"),
            bool_value(value, "serviceAccountsEnabled"),
            bool_value(value, "standardFlowEnabled"),
            bool_value(value, "surrogateAuthRequired"),
            SqlValue::Text(client_uuid.to_string()),
            string_value(value, "baseUrl"),
            string_value(value, "clientAuthenticatorType"),
            SqlValue::Text(client_id.to_string()),
            string_value(value, "description"),
            string_value(value, "managementUrl"),
            string_value(value, "name"),
            string_value(value, "protocol"),
            SqlValue::Text(realm_id.to_string()),
            string_value(value, "registrationToken"),
            string_value(value, "rootUrl"),
            string_value(value, "secret"),
        ],
    )
    .context("insert client row")?;
    Ok(())
}

fn update_client_row(
    conn: &Connection,
    realm_id: &str,
    client_uuid: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE CLIENT SET ALWAYS_DISPLAY_IN_CONSOLE=?1, BEARER_ONLY=?2, CONSENT_REQUIRED=?3, DIRECT_ACCESS_GRANTS_ENABLED=?4, ENABLED=?5, FRONTCHANNEL_LOGOUT=?6, FULL_SCOPE_ALLOWED=?7, IMPLICIT_FLOW_ENABLED=?8, NODE_REREG_TIMEOUT=?9, NOT_BEFORE=?10, PUBLIC_CLIENT=?11, SERVICE_ACCOUNTS_ENABLED=?12, STANDARD_FLOW_ENABLED=?13, SURROGATE_AUTH_REQUIRED=?14, BASE_URL=?15, CLIENT_AUTHENTICATOR_TYPE=?16, CLIENT_ID=?17, DESCRIPTION=?18, MANAGEMENT_URL=?19, NAME=?20, PROTOCOL=?21, REGISTRATION_TOKEN=?22, ROOT_URL=?23, SECRET=?24 WHERE ID=?25 AND REALM_ID=?26",
        &[
            bool_value(value, "alwaysDisplayInConsole"),
            bool_value(value, "bearerOnly"),
            bool_value(value, "consentRequired"),
            bool_value(value, "directAccessGrantsEnabled"),
            bool_value(value, "enabled"),
            bool_value(value, "frontchannelLogout"),
            bool_value(value, "fullScopeAllowed"),
            bool_value(value, "implicitFlowEnabled"),
            int_value(value, "nodeReRegistrationTimeout"),
            int_value(value, "notBefore"),
            bool_value(value, "publicClient"),
            bool_value(value, "serviceAccountsEnabled"),
            bool_value(value, "standardFlowEnabled"),
            bool_value(value, "surrogateAuthRequired"),
            string_value(value, "baseUrl"),
            string_value(value, "clientAuthenticatorType"),
            string_value(value, "clientId"),
            string_value(value, "description"),
            string_value(value, "managementUrl"),
            string_value(value, "name"),
            string_value(value, "protocol"),
            string_value(value, "registrationToken"),
            string_value(value, "rootUrl"),
            string_value(value, "secret"),
            SqlValue::Text(client_uuid.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update client row")?;
    Ok(())
}

fn insert_client_children(conn: &Connection, client_uuid: &str, value: &JsonValue) -> Result<()> {
    insert_client_attributes(conn, client_uuid, value)?;
    insert_client_redirect_uris(conn, client_uuid, value)?;
    insert_client_web_origins(conn, client_uuid, value)?;
    Ok(())
}

fn update_client_children(
    conn: &Connection,
    client_uuid: &str,
    patch: &JsonValue,
    merged: &JsonValue,
) -> Result<()> {
    if has_key(patch, "attributes") {
        delete_client_child_table(conn, client_uuid, "CLIENT_ATTRIBUTES")?;
        insert_client_attributes(conn, client_uuid, merged)?;
    }
    if has_key(patch, "redirectUris") {
        delete_client_child_table(conn, client_uuid, "REDIRECT_URIS")?;
        insert_client_redirect_uris(conn, client_uuid, merged)?;
    }
    if has_key(patch, "webOrigins") {
        delete_client_child_table(conn, client_uuid, "WEB_ORIGINS")?;
        insert_client_web_origins(conn, client_uuid, merged)?;
    }
    Ok(())
}

fn delete_client_children(conn: &Connection, client_uuid: &str) -> Result<()> {
    let tables = ["CLIENT_ATTRIBUTES", "REDIRECT_URIS", "WEB_ORIGINS"];
    for table in tables {
        delete_client_child_table(conn, client_uuid, table)?;
    }
    Ok(())
}

fn delete_client_child_table(conn: &Connection, client_uuid: &str, table: &str) -> Result<()> {
    conn.execute(
        &format!("DELETE FROM {table} WHERE CLIENT_ID=?1"),
        &[SqlValue::Text(client_uuid.to_string())],
    )
    .with_context(|| format!("delete client children in {table}"))?;
    Ok(())
}

fn insert_client_attributes(conn: &Connection, client_uuid: &str, value: &JsonValue) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in attrs {
        conn.execute(
            "INSERT INTO CLIENT_ATTRIBUTES (CLIENT_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(client_uuid.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert client attribute")?;
    }
    Ok(())
}

fn insert_client_redirect_uris(
    conn: &Connection,
    client_uuid: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("redirectUris").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for uri in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO REDIRECT_URIS (CLIENT_ID, VALUE) VALUES (?1, ?2)",
            &[SqlValue::Text(client_uuid.to_string()), SqlValue::Text(uri.to_string())],
        )
        .context("insert redirect uri")?;
    }
    Ok(())
}

fn insert_client_web_origins(
    conn: &Connection,
    client_uuid: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(values) = value.get("webOrigins").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for origin in values.iter().filter_map(|v| v.as_str()) {
        conn.execute(
            "INSERT INTO WEB_ORIGINS (CLIENT_ID, VALUE) VALUES (?1, ?2)",
            &[
                SqlValue::Text(client_uuid.to_string()),
                SqlValue::Text(origin.to_string()),
            ],
        )
        .context("insert web origin")?;
    }
    Ok(())
}

fn delete_realm_child_table(conn: &Connection, realm_id: &str, table: &str) -> Result<()> {
    conn.execute(
        &format!("DELETE FROM {table} WHERE REALM_ID=?1"),
        &[SqlValue::Text(realm_id.to_string())],
    )
    .with_context(|| format!("delete realm children in {table}"))?;
    Ok(())
}

fn update_realm_children(
    conn: &Connection,
    realm_id: &str,
    patch: &JsonValue,
    merged: &JsonValue,
) -> Result<()> {
    if has_key(patch, "attributes") {
        delete_realm_child_table(conn, realm_id, "REALM_ATTRIBUTE")?;
        insert_realm_attributes(conn, realm_id, merged)?;
    }
    if has_key(patch, "smtpServer") {
        delete_realm_child_table(conn, realm_id, "REALM_SMTP_CONFIG")?;
        insert_realm_smtp_config(conn, realm_id, merged)?;
    }
    if has_key(patch, "supportedLocales") {
        delete_realm_child_table(conn, realm_id, "REALM_SUPPORTED_LOCALES")?;
        insert_realm_supported_locales(conn, realm_id, merged)?;
    }
    if has_key(patch, "eventsListeners") {
        delete_realm_child_table(conn, realm_id, "REALM_EVENTS_LISTENERS")?;
        insert_realm_events_listeners(conn, realm_id, merged)?;
    }
    if has_key(patch, "enabledEventTypes") {
        delete_realm_child_table(conn, realm_id, "REALM_ENABLED_EVENT_TYPES")?;
        insert_realm_enabled_event_types(conn, realm_id, merged)?;
    }
    if has_key(patch, "defaultGroups") {
        delete_realm_child_table(conn, realm_id, "REALM_DEFAULT_GROUPS")?;
        insert_realm_default_groups(conn, realm_id, merged)?;
    }
    if has_key(patch, "requiredCredentials") {
        delete_realm_child_table(conn, realm_id, "REALM_REQUIRED_CREDENTIAL")?;
        insert_realm_required_credentials(conn, realm_id, merged)?;
    }
    let has_localizations = has_key(patch, "localizationTexts") || has_key(patch, "localizations");
    if has_localizations {
        delete_realm_child_table(conn, realm_id, "REALM_LOCALIZATIONS")?;
        insert_realm_localizations(conn, realm_id, merged)?;
    }
    Ok(())
}

fn load_realm(conn: &Connection, id: &str, name: &str) -> Result<JsonValue> {
    let rows = conn
        .execute(
            "SELECT * FROM REALM WHERE ID=?1",
            &[SqlValue::Text(id.to_string())],
        )
        .context("load realm row")?;
    let Some(row) = rows.rows().next() else {
        return Ok(json!({"id": id, "realm": name}));
    };

    let mut value = json!({"id": id, "realm": name});
    set_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    set_string(&mut value, "sslRequired", row.get::<&str>("SSL_REQUIRED"));
    set_bool(&mut value, "registrationAllowed", row.get::<i64>("REGISTRATION_ALLOWED"));
    set_bool(&mut value, "loginWithEmailAllowed", row.get::<i64>("LOGIN_WITH_EMAIL_ALLOWED"));
    set_bool(&mut value, "duplicateEmailsAllowed", row.get::<i64>("DUPLICATE_EMAILS_ALLOWED"));
    set_bool(&mut value, "resetPasswordAllowed", row.get::<i64>("RESET_PASSWORD_ALLOWED"));
    set_bool(&mut value, "editUsernameAllowed", row.get::<i64>("EDIT_USERNAME_ALLOWED"));
    set_bool(&mut value, "rememberMe", row.get::<i64>("REMEMBER_ME"));
    set_bool(&mut value, "verifyEmail", row.get::<i64>("VERIFY_EMAIL"));
    set_bool(
        &mut value,
        "internationalizationEnabled",
        row.get::<i64>("INTERNATIONALIZATION_ENABLED"),
    );
    set_string(&mut value, "defaultLocale", row.get::<&str>("DEFAULT_LOCALE"));
    set_string(&mut value, "loginTheme", row.get::<&str>("LOGIN_THEME"));
    set_string(&mut value, "accountTheme", row.get::<&str>("ACCOUNT_THEME"));
    set_string(&mut value, "adminTheme", row.get::<&str>("ADMIN_THEME"));
    set_string(&mut value, "emailTheme", row.get::<&str>("EMAIL_THEME"));
    set_bool(&mut value, "eventsEnabled", row.get::<i64>("EVENTS_ENABLED"));
    set_int(&mut value, "eventsExpiration", row.get::<i64>("EVENTS_EXPIRATION"));
    set_bool(&mut value, "adminEventsEnabled", row.get::<i64>("ADMIN_EVENTS_ENABLED"));
    set_bool(
        &mut value,
        "adminEventsDetailsEnabled",
        row.get::<i64>("ADMIN_EVENTS_DETAILS_ENABLED"),
    );
    set_string(&mut value, "passwordPolicy", row.get::<&str>("PASSWORD_POLICY"));
    set_string(&mut value, "otpPolicyAlg", row.get::<&str>("OTP_POLICY_ALG"));
    set_string(&mut value, "otpPolicyType", row.get::<&str>("OTP_POLICY_TYPE"));
    set_int(&mut value, "otpPolicyDigits", row.get::<i64>("OTP_POLICY_DIGITS"));
    set_int(&mut value, "otpPolicyPeriod", row.get::<i64>("OTP_POLICY_PERIOD"));
    set_int(&mut value, "otpPolicyCounter", row.get::<i64>("OTP_POLICY_COUNTER"));
    set_int(&mut value, "otpPolicyWindow", row.get::<i64>("OTP_POLICY_WINDOW"));
    set_int(&mut value, "accessTokenLifespan", row.get::<i64>("ACCESS_TOKEN_LIFESPAN"));
    set_int(&mut value, "ssoSessionIdleTimeout", row.get::<i64>("SSO_IDLE_TIMEOUT"));
    set_int(&mut value, "ssoSessionMaxLifespan", row.get::<i64>("SSO_MAX_LIFESPAN"));
    set_int(
        &mut value,
        "offlineSessionIdleTimeout",
        row.get::<i64>("OFFLINE_SESSION_IDLE_TIMEOUT"),
    );
    set_int(&mut value, "accessCodeLifespan", row.get::<i64>("ACCESS_CODE_LIFESPAN"));
    set_int(&mut value, "loginLifespan", row.get::<i64>("LOGIN_LIFESPAN"));
    set_int(&mut value, "userActionLifespan", row.get::<i64>("USER_ACTION_LIFESPAN"));
    set_int(&mut value, "notBefore", row.get::<i64>("NOT_BEFORE"));
    set_int(&mut value, "refreshTokenMaxReuse", row.get::<i64>("REFRESH_TOKEN_MAX_REUSE"));
    set_bool(&mut value, "revokeRefreshToken", row.get::<i64>("REVOKE_REFRESH_TOKEN"));
    set_bool(
        &mut value,
        "registrationEmailAsUsername",
        row.get::<i64>("REG_EMAIL_AS_USERNAME"),
    );
    set_string(&mut value, "registrationFlow", row.get::<&str>("REGISTRATION_FLOW"));
    set_string(
        &mut value,
        "resetCredentialsFlow",
        row.get::<&str>("RESET_CREDENTIALS_FLOW"),
    );
    set_string(&mut value, "browserFlow", row.get::<&str>("BROWSER_FLOW"));
    set_string(&mut value, "directGrantFlow", row.get::<&str>("DIRECT_GRANT_FLOW"));
    set_string(&mut value, "clientAuthenticationFlow", row.get::<&str>("CLIENT_AUTH_FLOW"));
    set_string(&mut value, "dockerAuthenticationFlow", row.get::<&str>("DOCKER_AUTH_FLOW"));
    set_string(&mut value, "masterAdminClient", row.get::<&str>("MASTER_ADMIN_CLIENT"));
    set_string(&mut value, "defaultRole", row.get::<&str>("DEFAULT_ROLE"));

    value["attributes"] = JsonValue::Object(load_kv_map(conn, "REALM_ATTRIBUTE", id)?);
    value["smtpServer"] = JsonValue::Object(load_kv_map(conn, "REALM_SMTP_CONFIG", id)?);
    value["supportedLocales"] =
        JsonValue::Array(load_values(conn, "REALM_SUPPORTED_LOCALES", id)?);
    value["eventsListeners"] =
        JsonValue::Array(load_values(conn, "REALM_EVENTS_LISTENERS", id)?);
    value["enabledEventTypes"] =
        JsonValue::Array(load_values(conn, "REALM_ENABLED_EVENT_TYPES", id)?);
    value["defaultGroups"] = JsonValue::Array(load_default_groups(conn, id)?);
    value["requiredCredentials"] = JsonValue::Array(load_required_credentials(conn, id)?);
    value["localizationTexts"] = JsonValue::Object(load_localizations(conn, id)?);

    Ok(value)
}

fn load_kv_map(
    conn: &Connection,
    table: &str,
    realm_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            &format!("SELECT NAME, VALUE FROM {table} WHERE REALM_ID=?1"),
            &[SqlValue::Text(realm_id.to_string())],
        )
        .with_context(|| format!("load {table}"))?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn load_values(conn: &Connection, table: &str, realm_id: &str) -> Result<Vec<JsonValue>> {
    let mut values = Vec::new();
    let rows = conn
        .execute(
            &format!("SELECT VALUE FROM {table} WHERE REALM_ID=?1"),
            &[SqlValue::Text(realm_id.to_string())],
        )
        .with_context(|| format!("load {table}"))?;
    for row in rows.rows() {
        if let Some(value) = row.get::<&str>("VALUE") {
            values.push(JsonValue::String(value.to_string()));
        }
    }
    Ok(values)
}

fn load_default_groups(conn: &Connection, realm_id: &str) -> Result<Vec<JsonValue>> {
    let mut values = Vec::new();
    let rows = conn
        .execute(
            "SELECT GROUP_ID FROM REALM_DEFAULT_GROUPS WHERE REALM_ID=?1",
            &[SqlValue::Text(realm_id.to_string())],
        )
        .context("load default groups")?;
    for row in rows.rows() {
        if let Some(group) = row.get::<&str>("GROUP_ID") {
            values.push(JsonValue::String(group.to_string()));
        }
    }
    Ok(values)
}

fn load_required_credentials(conn: &Connection, realm_id: &str) -> Result<Vec<JsonValue>> {
    let mut values = Vec::new();
    let rows = conn
        .execute(
            "SELECT TYPE, SECRET, INPUT, FORM_LABEL FROM REALM_REQUIRED_CREDENTIAL WHERE REALM_ID=?1",
            &[SqlValue::Text(realm_id.to_string())],
        )
        .context("load required credentials")?;
    for row in rows.rows() {
        let cred_type = row.get::<&str>("TYPE").unwrap_or("");
        let secret = row.get::<i64>("SECRET").map(|v| v != 0).unwrap_or(false);
        let input = row.get::<i64>("INPUT").map(|v| v != 0).unwrap_or(false);
        let form_label = row.get::<&str>("FORM_LABEL");
        let mut cred = json!({"type": cred_type, "secret": secret, "input": input});
        if let Some(label) = form_label {
            cred["formLabel"] = JsonValue::String(label.to_string());
        }
        values.push(cred);
    }
    Ok(values)
}

fn load_client_by_id(
    conn: &Connection,
    realm_id: &str,
    client_uuid: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT * FROM CLIENT WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(client_uuid.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load client row")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };

    let mut value = JsonValue::Object(serde_json::Map::new());
    set_string(&mut value, "id", row.get::<&str>("ID"));
    set_string(&mut value, "clientId", row.get::<&str>("CLIENT_ID"));
    set_string(&mut value, "name", row.get::<&str>("NAME"));
    set_string(&mut value, "description", row.get::<&str>("DESCRIPTION"));
    set_string(&mut value, "protocol", row.get::<&str>("PROTOCOL"));
    set_string(&mut value, "rootUrl", row.get::<&str>("ROOT_URL"));
    set_string(&mut value, "baseUrl", row.get::<&str>("BASE_URL"));
    set_string(&mut value, "managementUrl", row.get::<&str>("MANAGEMENT_URL"));
    set_string(
        &mut value,
        "clientAuthenticatorType",
        row.get::<&str>("CLIENT_AUTHENTICATOR_TYPE"),
    );
    set_string(&mut value, "registrationToken", row.get::<&str>("REGISTRATION_TOKEN"));
    set_string(&mut value, "secret", row.get::<&str>("SECRET"));
    set_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    set_bool(&mut value, "publicClient", row.get::<i64>("PUBLIC_CLIENT"));
    set_bool(&mut value, "bearerOnly", row.get::<i64>("BEARER_ONLY"));
    set_bool(
        &mut value,
        "consentRequired",
        row.get::<i64>("CONSENT_REQUIRED"),
    );
    set_bool(
        &mut value,
        "directAccessGrantsEnabled",
        row.get::<i64>("DIRECT_ACCESS_GRANTS_ENABLED"),
    );
    set_bool(
        &mut value,
        "standardFlowEnabled",
        row.get::<i64>("STANDARD_FLOW_ENABLED"),
    );
    set_bool(
        &mut value,
        "implicitFlowEnabled",
        row.get::<i64>("IMPLICIT_FLOW_ENABLED"),
    );
    set_bool(
        &mut value,
        "serviceAccountsEnabled",
        row.get::<i64>("SERVICE_ACCOUNTS_ENABLED"),
    );
    set_bool(
        &mut value,
        "frontchannelLogout",
        row.get::<i64>("FRONTCHANNEL_LOGOUT"),
    );
    set_bool(
        &mut value,
        "fullScopeAllowed",
        row.get::<i64>("FULL_SCOPE_ALLOWED"),
    );
    set_bool(
        &mut value,
        "alwaysDisplayInConsole",
        row.get::<i64>("ALWAYS_DISPLAY_IN_CONSOLE"),
    );
    set_bool(
        &mut value,
        "surrogateAuthRequired",
        row.get::<i64>("SURROGATE_AUTH_REQUIRED"),
    );
    set_int(
        &mut value,
        "nodeReRegistrationTimeout",
        row.get::<i64>("NODE_REREG_TIMEOUT"),
    );
    set_int(&mut value, "notBefore", row.get::<i64>("NOT_BEFORE"));

    value["attributes"] = JsonValue::Object(load_client_kv_map(conn, "CLIENT_ATTRIBUTES", client_uuid)?);
    value["redirectUris"] =
        JsonValue::Array(load_client_values(conn, "REDIRECT_URIS", client_uuid)?);
    value["webOrigins"] =
        JsonValue::Array(load_client_values(conn, "WEB_ORIGINS", client_uuid)?);

    Ok(Some(value))
}

fn load_client_kv_map(
    conn: &Connection,
    table: &str,
    client_uuid: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            &format!("SELECT NAME, VALUE FROM {table} WHERE CLIENT_ID=?1"),
            &[SqlValue::Text(client_uuid.to_string())],
        )
        .with_context(|| format!("load {table}"))?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn load_client_values(conn: &Connection, table: &str, client_uuid: &str) -> Result<Vec<JsonValue>> {
    let mut values = Vec::new();
    let rows = conn
        .execute(
            &format!("SELECT VALUE FROM {table} WHERE CLIENT_ID=?1"),
            &[SqlValue::Text(client_uuid.to_string())],
        )
        .with_context(|| format!("load {table}"))?;
    for row in rows.rows() {
        if let Some(value) = row.get::<&str>("VALUE") {
            values.push(JsonValue::String(value.to_string()));
        }
    }
    Ok(values)
}

fn client_id_exists(conn: &Connection, realm_id: &str, client_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT WHERE CLIENT_ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(client_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check clientId")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn client_uuid_exists(conn: &Connection, client_uuid: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT WHERE ID=?1",
            &[SqlValue::Text(client_uuid.to_string())],
        )
        .context("check client uuid")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn client_scope_name_exists(conn: &Connection, realm_id: &str, name: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT_SCOPE WHERE NAME=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(name.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check client scope name")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn client_scope_id_exists(conn: &Connection, scope_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT_SCOPE WHERE ID=?1",
            &[SqlValue::Text(scope_id.to_string())],
        )
        .context("check client scope id")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_client_scope(conn: &Connection, realm_id: &str, scope_id: &str) -> Result<()> {
    let rows = conn
        .execute(
            "SELECT ID FROM CLIENT_SCOPE WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(scope_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check client scope")?;
    if rows.rows().next().is_none() {
        return Err(anyhow!("client scope not found"));
    }
    Ok(())
}

fn insert_client_scope(
    conn: &Connection,
    realm_id: &str,
    scope_id: &str,
    name: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO CLIENT_SCOPE (ID, REALM_ID, NAME, DESCRIPTION, PROTOCOL) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            SqlValue::Text(scope_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
            SqlValue::Text(name.to_string()),
            string_value(value, "description"),
            string_value(value, "protocol"),
        ],
    )
    .context("insert client scope row")?;
    Ok(())
}

fn update_client_scope_row(
    conn: &Connection,
    realm_id: &str,
    scope_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE CLIENT_SCOPE SET NAME=?1, DESCRIPTION=?2, PROTOCOL=?3 WHERE ID=?4 AND REALM_ID=?5",
        &[
            string_value(value, "name"),
            string_value(value, "description"),
            string_value(value, "protocol"),
            SqlValue::Text(scope_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update client scope row")?;
    Ok(())
}

fn insert_client_scope_attributes(
    conn: &Connection,
    scope_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in attrs {
        conn.execute(
            "INSERT INTO CLIENT_SCOPE_ATTRIBUTES (SCOPE_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(scope_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert client scope attribute")?;
    }
    Ok(())
}

fn delete_client_scope_attributes(conn: &Connection, scope_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM CLIENT_SCOPE_ATTRIBUTES WHERE SCOPE_ID=?1",
        &[SqlValue::Text(scope_id.to_string())],
    )
    .context("delete client scope attributes")?;
    Ok(())
}

fn delete_client_scope_children(conn: &Connection, scope_id: &str) -> Result<()> {
    delete_client_scope_attributes(conn, scope_id)?;
    conn.execute(
        "DELETE FROM CLIENT_SCOPE_CLIENT WHERE SCOPE_ID=?1",
        &[SqlValue::Text(scope_id.to_string())],
    )
    .context("delete client scope client")?;
    conn.execute(
        "DELETE FROM DEFAULT_CLIENT_SCOPE WHERE SCOPE_ID=?1",
        &[SqlValue::Text(scope_id.to_string())],
    )
    .context("delete default client scope")?;
    conn.execute(
        "DELETE FROM CLIENT_SCOPE_ROLE_MAPPING WHERE SCOPE_ID=?1",
        &[SqlValue::Text(scope_id.to_string())],
    )
    .context("delete client scope role mapping")?;
    delete_protocol_mappers_by_scope(conn, scope_id)?;
    Ok(())
}

fn load_client_scope_by_id(
    conn: &Connection,
    realm_id: &str,
    scope_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, DESCRIPTION, PROTOCOL FROM CLIENT_SCOPE WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(scope_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load client scope")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "description", row.get::<&str>("DESCRIPTION"));
    set_opt_string(&mut value, "protocol", row.get::<&str>("PROTOCOL"));
    value["attributes"] =
        JsonValue::Object(load_client_scope_attributes(conn, scope_id)?);
    Ok(Some(value))
}

fn load_client_scope_attributes(
    conn: &Connection,
    scope_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM CLIENT_SCOPE_ATTRIBUTES WHERE SCOPE_ID=?1",
            &[SqlValue::Text(scope_id.to_string())],
        )
        .context("load client scope attributes")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn insert_protocol_mapper(
    conn: &Connection,
    scope_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let name = match value.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => return Err(anyhow!("name is required")),
    };
    let protocol = value.get("protocol").and_then(|v| v.as_str());
    let protocol_mapper = value.get("protocolMapper").and_then(|v| v.as_str());
    let mapper_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("mapper"));
    if protocol_mapper_exists(conn, &mapper_id)? {
        return Err(anyhow!("protocol mapper already exists"));
    }

    conn.execute(
        "INSERT INTO PROTOCOL_MAPPER (ID, CLIENT_SCOPE_ID, NAME, PROTOCOL, PROTOCOL_MAPPER_NAME) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            SqlValue::Text(mapper_id.clone()),
            SqlValue::Text(scope_id.to_string()),
            SqlValue::Text(name),
            protocol
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null),
            protocol_mapper
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null),
        ],
    )
    .context("insert protocol mapper")?;

    insert_protocol_mapper_config(conn, &mapper_id, value)?;
    Ok(())
}

fn update_protocol_mapper_row(
    conn: &Connection,
    mapper_id: &str,
    scope_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE PROTOCOL_MAPPER SET NAME=?1, PROTOCOL=?2, PROTOCOL_MAPPER_NAME=?3 WHERE ID=?4 AND CLIENT_SCOPE_ID=?5",
        &[
            string_value(value, "name"),
            string_value(value, "protocol"),
            string_value(value, "protocolMapper"),
            SqlValue::Text(mapper_id.to_string()),
            SqlValue::Text(scope_id.to_string()),
        ],
    )
    .context("update protocol mapper")?;
    Ok(())
}

fn insert_protocol_mapper_config(
    conn: &Connection,
    mapper_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(config) = value.get("config").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in config {
        conn.execute(
            "INSERT INTO PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(mapper_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert protocol mapper config")?;
    }
    Ok(())
}

fn delete_protocol_mapper_config(conn: &Connection, mapper_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM PROTOCOL_MAPPER_CONFIG WHERE PROTOCOL_MAPPER_ID=?1",
        &[SqlValue::Text(mapper_id.to_string())],
    )
    .context("delete protocol mapper config")?;
    Ok(())
}

fn delete_protocol_mappers_by_scope(conn: &Connection, scope_id: &str) -> Result<()> {
    let rows = conn
        .execute(
            "SELECT ID FROM PROTOCOL_MAPPER WHERE CLIENT_SCOPE_ID=?1",
            &[SqlValue::Text(scope_id.to_string())],
        )
        .context("load protocol mappers")?;
    for row in rows.rows() {
        if let Some(mapper_id) = row.get::<&str>("ID") {
            delete_protocol_mapper_config(conn, mapper_id)?;
        }
    }
    conn.execute(
        "DELETE FROM PROTOCOL_MAPPER WHERE CLIENT_SCOPE_ID=?1",
        &[SqlValue::Text(scope_id.to_string())],
    )
    .context("delete protocol mappers")?;
    Ok(())
}

fn protocol_mapper_exists(conn: &Connection, mapper_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM PROTOCOL_MAPPER WHERE ID=?1",
            &[SqlValue::Text(mapper_id.to_string())],
        )
        .context("check protocol mapper")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn load_protocol_mapper(conn: &Connection, mapper_id: &str) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, PROTOCOL, PROTOCOL_MAPPER_NAME FROM PROTOCOL_MAPPER WHERE ID=?1",
            &[SqlValue::Text(mapper_id.to_string())],
        )
        .context("load protocol mapper")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "protocol", row.get::<&str>("PROTOCOL"));
    set_opt_string(
        &mut value,
        "protocolMapper",
        row.get::<&str>("PROTOCOL_MAPPER_NAME"),
    );
    value["config"] = JsonValue::Object(load_protocol_mapper_config(conn, mapper_id)?);
    Ok(Some(value))
}

fn load_protocol_mapper_config(
    conn: &Connection,
    mapper_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM PROTOCOL_MAPPER_CONFIG WHERE PROTOCOL_MAPPER_ID=?1",
            &[SqlValue::Text(mapper_id.to_string())],
        )
        .context("load protocol mapper config")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn component_id_exists(conn: &Connection, component_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM COMPONENT WHERE ID=?1",
            &[SqlValue::Text(component_id.to_string())],
        )
        .context("check component id")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn component_in_realm(conn: &Connection, realm_id: &str, component_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM COMPONENT WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(component_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check component realm")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn load_component_by_id(conn: &Connection, component_id: &str) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, PROVIDER_ID, PROVIDER_TYPE, PARENT_ID, SUB_TYPE FROM COMPONENT WHERE ID=?1",
            &[SqlValue::Text(component_id.to_string())],
        )
        .context("load component")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "providerId", row.get::<&str>("PROVIDER_ID"));
    set_opt_string(&mut value, "providerType", row.get::<&str>("PROVIDER_TYPE"));
    set_opt_string(&mut value, "parentId", row.get::<&str>("PARENT_ID"));
    set_opt_string(&mut value, "subType", row.get::<&str>("SUB_TYPE"));
    value["config"] = JsonValue::Object(load_component_config(conn, component_id)?);
    Ok(Some(value))
}

fn load_component_by_id_in_realm(
    conn: &Connection,
    realm_id: &str,
    component_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, PROVIDER_ID, PROVIDER_TYPE, PARENT_ID, SUB_TYPE FROM COMPONENT WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(component_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load component in realm")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "providerId", row.get::<&str>("PROVIDER_ID"));
    set_opt_string(&mut value, "providerType", row.get::<&str>("PROVIDER_TYPE"));
    set_opt_string(&mut value, "parentId", row.get::<&str>("PARENT_ID"));
    set_opt_string(&mut value, "subType", row.get::<&str>("SUB_TYPE"));
    value["config"] = JsonValue::Object(load_component_config(conn, component_id)?);
    Ok(Some(value))
}

fn insert_component(
    conn: &Connection,
    realm_id: &str,
    component_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO COMPONENT (ID, REALM_ID, NAME, PARENT_ID, PROVIDER_ID, PROVIDER_TYPE, SUB_TYPE) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[
            SqlValue::Text(component_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
            string_value(value, "name"),
            string_value(value, "parentId"),
            string_value(value, "providerId"),
            string_value(value, "providerType"),
            string_value(value, "subType"),
        ],
    )
    .context("insert component")?;
    Ok(())
}

fn update_component_row(
    conn: &Connection,
    realm_id: &str,
    component_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE COMPONENT SET NAME=?1, PARENT_ID=?2, PROVIDER_ID=?3, PROVIDER_TYPE=?4, SUB_TYPE=?5 WHERE ID=?6 AND REALM_ID=?7",
        &[
            string_value(value, "name"),
            string_value(value, "parentId"),
            string_value(value, "providerId"),
            string_value(value, "providerType"),
            string_value(value, "subType"),
            SqlValue::Text(component_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update component")?;
    Ok(())
}

fn insert_component_config(conn: &Connection, component_id: &str, value: &JsonValue) -> Result<()> {
    let Some(config) = value.get("config").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in config {
        match val {
            JsonValue::Array(items) => {
                for item in items {
                    if let Some(entry) = item.as_str() {
                        conn.execute(
                            "INSERT INTO COMPONENT_CONFIG (ID, COMPONENT_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
                            &[
                                SqlValue::Text(generate_id("component-config")),
                                SqlValue::Text(component_id.to_string()),
                                SqlValue::Text(name.to_string()),
                                SqlValue::Text(entry.to_string()),
                            ],
                        )
                        .context("insert component config")?;
                    }
                }
            }
            JsonValue::String(entry) => {
                conn.execute(
                    "INSERT INTO COMPONENT_CONFIG (ID, COMPONENT_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqlValue::Text(generate_id("component-config")),
                        SqlValue::Text(component_id.to_string()),
                        SqlValue::Text(name.to_string()),
                        SqlValue::Text(entry.to_string()),
                    ],
                )
                .context("insert component config")?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn delete_component_config(conn: &Connection, component_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM COMPONENT_CONFIG WHERE COMPONENT_ID=?1",
        &[SqlValue::Text(component_id.to_string())],
    )
    .context("delete component config")?;
    Ok(())
}

fn load_component_config(
    conn: &Connection,
    component_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM COMPONENT_CONFIG WHERE COMPONENT_ID=?1 ORDER BY NAME, ID",
            &[SqlValue::Text(component_id.to_string())],
        )
        .context("load component config")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        grouped
            .entry(name.to_string())
            .or_default()
            .push(value.to_string());
    }
    let mut map = serde_json::Map::new();
    for (name, values) in grouped {
        let items = values
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        map.insert(name, JsonValue::Array(items));
    }
    Ok(map)
}

fn group_id_exists(conn: &Connection, group_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM KEYCLOAK_GROUP WHERE ID=?1",
            &[SqlValue::Text(group_id.to_string())],
        )
        .context("check group id")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn group_in_realm(conn: &Connection, realm_id: &str, group_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM KEYCLOAK_GROUP WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(group_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check group realm")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn insert_group(
    conn: &Connection,
    realm_id: &str,
    group_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO KEYCLOAK_GROUP (ID, REALM_ID, NAME, DESCRIPTION, PARENT_GROUP) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            SqlValue::Text(group_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
            string_value(value, "name"),
            string_value(value, "description"),
            group_parent_value(value),
        ],
    )
    .context("insert group")?;
    Ok(())
}

fn update_group_row(
    conn: &Connection,
    realm_id: &str,
    group_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE KEYCLOAK_GROUP SET NAME=?1, DESCRIPTION=?2, PARENT_GROUP=?3 WHERE ID=?4 AND REALM_ID=?5",
        &[
            string_value(value, "name"),
            string_value(value, "description"),
            group_parent_value(value),
            SqlValue::Text(group_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update group row")?;
    Ok(())
}

fn group_parent_value(value: &JsonValue) -> SqlValue {
    value
        .get("parentId")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(|v| SqlValue::Text(v.to_string()))
        .unwrap_or(SqlValue::Null)
}

fn insert_group_attributes(conn: &Connection, group_id: &str, value: &JsonValue) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in attrs {
        match val {
            JsonValue::Array(items) => {
                for item in items {
                    let entry = item.as_str().map(|v| v.to_string()).unwrap_or_else(|| {
                        json_to_string(item)
                    });
                    insert_group_attribute(conn, group_id, name, &entry)?;
                }
            }
            JsonValue::String(entry) => {
                insert_group_attribute(conn, group_id, name, entry)?;
            }
            _ => {
                let entry = json_to_string(val);
                insert_group_attribute(conn, group_id, name, &entry)?;
            }
        }
    }
    Ok(())
}

fn insert_group_attribute(
    conn: &Connection,
    group_id: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO GROUP_ATTRIBUTE (ID, GROUP_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
        &[
            SqlValue::Text(generate_id("group-attr")),
            SqlValue::Text(group_id.to_string()),
            SqlValue::Text(name.to_string()),
            SqlValue::Text(value.to_string()),
        ],
    )
    .context("insert group attribute")?;
    Ok(())
}

fn delete_group_attributes(conn: &Connection, group_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM GROUP_ATTRIBUTE WHERE GROUP_ID=?1",
        &[SqlValue::Text(group_id.to_string())],
    )
    .context("delete group attributes")?;
    Ok(())
}

fn load_group_attributes(
    conn: &Connection,
    group_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM GROUP_ATTRIBUTE WHERE GROUP_ID=?1 ORDER BY NAME, ID",
            &[SqlValue::Text(group_id.to_string())],
        )
        .context("load group attributes")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        grouped
            .entry(name.to_string())
            .or_default()
            .push(value.to_string());
    }
    let mut map = serde_json::Map::new();
    for (name, values) in grouped {
        let items = values
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        map.insert(name, JsonValue::Array(items));
    }
    Ok(map)
}

fn load_group_representation(
    conn: &Connection,
    realm_id: &str,
    group_id: &str,
    include_subgroups: bool,
    include_subgroup_count: bool,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, DESCRIPTION, PARENT_GROUP FROM KEYCLOAK_GROUP WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(group_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load group")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "description", row.get::<&str>("DESCRIPTION"));
    set_opt_string(&mut value, "parentId", row.get::<&str>("PARENT_GROUP"));
    value["path"] = JsonValue::String(load_group_path(conn, realm_id, group_id)?);
    value["attributes"] = JsonValue::Object(load_group_attributes(conn, group_id)?);

    if include_subgroup_count {
        let count = count_group_children(conn, realm_id, group_id)?;
        value["subGroupCount"] = JsonValue::Number(count.into());
    }
    if include_subgroups {
        let mut sub_groups = Vec::new();
        let rows = conn
            .execute(
                "SELECT ID FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND PARENT_GROUP=?2 ORDER BY NAME",
                &[
                    SqlValue::Text(realm_id.to_string()),
                    SqlValue::Text(group_id.to_string()),
                ],
            )
            .context("load group children")?;
        for row in rows.rows() {
            let Some(child_id) = row.get::<&str>("ID") else {
                continue;
            };
            if let Some(child) = load_group_representation(
                conn,
                realm_id,
                child_id,
                include_subgroups,
                include_subgroup_count,
            )? {
                sub_groups.push(child);
            }
        }
        value["subGroups"] = JsonValue::Array(sub_groups);
    }
    Ok(Some(value))
}

fn load_group_path(conn: &Connection, realm_id: &str, group_id: &str) -> Result<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = Some(group_id.to_string());
    let mut guard = 0;
    while let Some(current_id) = current {
        guard += 1;
        if guard > 128 {
            break;
        }
        let rows = conn
            .execute(
                "SELECT NAME, PARENT_GROUP FROM KEYCLOAK_GROUP WHERE ID=?1 AND REALM_ID=?2",
                &[
                    SqlValue::Text(current_id.to_string()),
                    SqlValue::Text(realm_id.to_string()),
                ],
            )
            .context("load group path")?;
        let Some(row) = rows.rows().next() else {
            break;
        };
        if let Some(name) = row.get::<&str>("NAME") {
            segments.push(name.to_string());
        }
        current = row.get::<&str>("PARENT_GROUP").map(|v| v.to_string());
    }
    segments.reverse();
    Ok(format!("/{}", segments.join("/")))
}

fn count_group_children(conn: &Connection, realm_id: &str, group_id: &str) -> Result<i64> {
    let rows = conn
        .execute(
            "SELECT COUNT(*) AS CNT FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND PARENT_GROUP=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(group_id.to_string()),
            ],
        )
        .context("count group children")?;
    let mut count = 0;
    if let Some(row) = rows.rows().next() {
        count = row.get::<i64>("CNT").unwrap_or(0);
    }
    Ok(count)
}

fn find_group_by_name_parent(
    conn: &Connection,
    realm_id: &str,
    name: &str,
    parent_id: Option<&str>,
) -> Result<Option<String>> {
    let (sql, values) = if let Some(parent_id) = parent_id {
        (
            "SELECT ID FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND NAME=?2 AND PARENT_GROUP=?3",
            vec![
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(parent_id.to_string()),
            ],
        )
    } else {
        (
            "SELECT ID FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND NAME=?2 AND PARENT_GROUP IS NULL",
            vec![
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(name.to_string()),
            ],
        )
    };
    let rows = conn.execute(sql, &values).context("find group by name")?;
    for row in rows.rows() {
        if let Some(id) = row.get::<&str>("ID") {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

fn delete_group_recursive(conn: &Connection, realm_id: &str, group_id: &str) -> Result<()> {
    let rows = conn
        .execute(
            "SELECT ID FROM KEYCLOAK_GROUP WHERE REALM_ID=?1 AND PARENT_GROUP=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(group_id.to_string()),
            ],
        )
        .context("load child groups")?;
    let mut child_ids = Vec::new();
    for row in rows.rows() {
        if let Some(id) = row.get::<&str>("ID") {
            child_ids.push(id.to_string());
        }
    }
    for child_id in child_ids {
        delete_group_recursive(conn, realm_id, &child_id)?;
    }
    delete_group_attributes(conn, group_id)?;
    conn.execute(
        "DELETE FROM GROUP_ROLE_MAPPING WHERE GROUP_ID=?1",
        &[SqlValue::Text(group_id.to_string())],
    )
    .context("delete group role mappings")?;
    conn.execute(
        "DELETE FROM KEYCLOAK_GROUP WHERE ID=?1 AND REALM_ID=?2",
        &[
            SqlValue::Text(group_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("delete group")?;
    Ok(())
}

fn identity_provider_alias_exists(
    conn: &Connection,
    realm_id: &str,
    alias: &str,
) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT INTERNAL_ID FROM IDENTITY_PROVIDER WHERE REALM_ID=?1 AND PROVIDER_ALIAS=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("check identity provider alias")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn insert_identity_provider(
    conn: &Connection,
    realm_id: &str,
    internal_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO IDENTITY_PROVIDER (ADD_TOKEN_ROLE, AUTHENTICATE_BY_DEFAULT, ENABLED, HIDE_ON_LOGIN, LINK_ONLY, STORE_TOKEN, TRUST_EMAIL, INTERNAL_ID, FIRST_BROKER_LOGIN_FLOW_ID, ORGANIZATION_ID, POST_BROKER_LOGIN_FLOW_ID, PROVIDER_ALIAS, PROVIDER_DISPLAY_NAME, PROVIDER_ID, REALM_ID) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        &[
            bool_value(value, "addReadTokenRoleOnCreate"),
            bool_value(value, "authenticateByDefault"),
            bool_value(value, "enabled"),
            bool_value(value, "hideOnLogin"),
            bool_value(value, "linkOnly"),
            bool_value(value, "storeToken"),
            bool_value(value, "trustEmail"),
            SqlValue::Text(internal_id.to_string()),
            string_value(value, "firstBrokerLoginFlowAlias"),
            string_value(value, "organizationId"),
            string_value(value, "postBrokerLoginFlowAlias"),
            string_value(value, "alias"),
            string_value(value, "displayName"),
            string_value(value, "providerId"),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("insert identity provider")?;
    Ok(())
}

fn update_identity_provider_row(
    conn: &Connection,
    realm_id: &str,
    internal_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE IDENTITY_PROVIDER SET ADD_TOKEN_ROLE=?1, AUTHENTICATE_BY_DEFAULT=?2, ENABLED=?3, HIDE_ON_LOGIN=?4, LINK_ONLY=?5, STORE_TOKEN=?6, TRUST_EMAIL=?7, FIRST_BROKER_LOGIN_FLOW_ID=?8, ORGANIZATION_ID=?9, POST_BROKER_LOGIN_FLOW_ID=?10, PROVIDER_ALIAS=?11, PROVIDER_DISPLAY_NAME=?12, PROVIDER_ID=?13 WHERE INTERNAL_ID=?14 AND REALM_ID=?15",
        &[
            bool_value(value, "addReadTokenRoleOnCreate"),
            bool_value(value, "authenticateByDefault"),
            bool_value(value, "enabled"),
            bool_value(value, "hideOnLogin"),
            bool_value(value, "linkOnly"),
            bool_value(value, "storeToken"),
            bool_value(value, "trustEmail"),
            string_value(value, "firstBrokerLoginFlowAlias"),
            string_value(value, "organizationId"),
            string_value(value, "postBrokerLoginFlowAlias"),
            string_value(value, "alias"),
            string_value(value, "displayName"),
            string_value(value, "providerId"),
            SqlValue::Text(internal_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update identity provider")?;
    Ok(())
}

fn load_identity_provider_by_alias(
    conn: &Connection,
    realm_id: &str,
    alias: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ADD_TOKEN_ROLE, AUTHENTICATE_BY_DEFAULT, ENABLED, HIDE_ON_LOGIN, LINK_ONLY, STORE_TOKEN, TRUST_EMAIL, INTERNAL_ID, FIRST_BROKER_LOGIN_FLOW_ID, ORGANIZATION_ID, POST_BROKER_LOGIN_FLOW_ID, PROVIDER_ALIAS, PROVIDER_DISPLAY_NAME, PROVIDER_ID FROM IDENTITY_PROVIDER WHERE REALM_ID=?1 AND PROVIDER_ALIAS=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("load identity provider")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "alias", row.get::<&str>("PROVIDER_ALIAS"));
    set_opt_string(
        &mut value,
        "displayName",
        row.get::<&str>("PROVIDER_DISPLAY_NAME"),
    );
    set_opt_string(&mut value, "internalId", row.get::<&str>("INTERNAL_ID"));
    set_opt_string(&mut value, "providerId", row.get::<&str>("PROVIDER_ID"));
    set_opt_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    set_opt_bool(
        &mut value,
        "addReadTokenRoleOnCreate",
        row.get::<i64>("ADD_TOKEN_ROLE"),
    );
    set_opt_bool(
        &mut value,
        "authenticateByDefault",
        row.get::<i64>("AUTHENTICATE_BY_DEFAULT"),
    );
    set_opt_bool(&mut value, "storeToken", row.get::<i64>("STORE_TOKEN"));
    set_opt_bool(&mut value, "trustEmail", row.get::<i64>("TRUST_EMAIL"));
    set_opt_bool(&mut value, "linkOnly", row.get::<i64>("LINK_ONLY"));
    set_opt_bool(&mut value, "hideOnLogin", row.get::<i64>("HIDE_ON_LOGIN"));
    set_opt_string(
        &mut value,
        "firstBrokerLoginFlowAlias",
        row.get::<&str>("FIRST_BROKER_LOGIN_FLOW_ID"),
    );
    set_opt_string(
        &mut value,
        "postBrokerLoginFlowAlias",
        row.get::<&str>("POST_BROKER_LOGIN_FLOW_ID"),
    );
    set_opt_string(&mut value, "organizationId", row.get::<&str>("ORGANIZATION_ID"));
    value["config"] = JsonValue::Object(load_identity_provider_config(
        conn,
        row.get::<&str>("INTERNAL_ID").unwrap_or(""),
    )?);
    Ok(Some(value))
}

fn load_identity_provider_by_internal_id(
    conn: &Connection,
    realm_id: &str,
    internal_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ADD_TOKEN_ROLE, AUTHENTICATE_BY_DEFAULT, ENABLED, HIDE_ON_LOGIN, LINK_ONLY, STORE_TOKEN, TRUST_EMAIL, INTERNAL_ID, FIRST_BROKER_LOGIN_FLOW_ID, ORGANIZATION_ID, POST_BROKER_LOGIN_FLOW_ID, PROVIDER_ALIAS, PROVIDER_DISPLAY_NAME, PROVIDER_ID FROM IDENTITY_PROVIDER WHERE REALM_ID=?1 AND INTERNAL_ID=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(internal_id.to_string()),
            ],
        )
        .context("load identity provider")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "alias", row.get::<&str>("PROVIDER_ALIAS"));
    set_opt_string(
        &mut value,
        "displayName",
        row.get::<&str>("PROVIDER_DISPLAY_NAME"),
    );
    set_opt_string(&mut value, "internalId", row.get::<&str>("INTERNAL_ID"));
    set_opt_string(&mut value, "providerId", row.get::<&str>("PROVIDER_ID"));
    set_opt_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    set_opt_bool(
        &mut value,
        "addReadTokenRoleOnCreate",
        row.get::<i64>("ADD_TOKEN_ROLE"),
    );
    set_opt_bool(
        &mut value,
        "authenticateByDefault",
        row.get::<i64>("AUTHENTICATE_BY_DEFAULT"),
    );
    set_opt_bool(&mut value, "storeToken", row.get::<i64>("STORE_TOKEN"));
    set_opt_bool(&mut value, "trustEmail", row.get::<i64>("TRUST_EMAIL"));
    set_opt_bool(&mut value, "linkOnly", row.get::<i64>("LINK_ONLY"));
    set_opt_bool(&mut value, "hideOnLogin", row.get::<i64>("HIDE_ON_LOGIN"));
    set_opt_string(
        &mut value,
        "firstBrokerLoginFlowAlias",
        row.get::<&str>("FIRST_BROKER_LOGIN_FLOW_ID"),
    );
    set_opt_string(
        &mut value,
        "postBrokerLoginFlowAlias",
        row.get::<&str>("POST_BROKER_LOGIN_FLOW_ID"),
    );
    set_opt_string(&mut value, "organizationId", row.get::<&str>("ORGANIZATION_ID"));
    value["config"] = JsonValue::Object(load_identity_provider_config(
        conn,
        row.get::<&str>("INTERNAL_ID").unwrap_or(""),
    )?);
    Ok(Some(value))
}

fn load_identity_provider_config(
    conn: &Connection,
    internal_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM IDENTITY_PROVIDER_CONFIG WHERE IDENTITY_PROVIDER_ID=?1",
            &[SqlValue::Text(internal_id.to_string())],
        )
        .context("load identity provider config")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn insert_identity_provider_config(
    conn: &Connection,
    internal_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(config) = value.get("config").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in config {
        conn.execute(
            "INSERT INTO IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(internal_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert identity provider config")?;
    }
    Ok(())
}

fn delete_identity_provider_config(conn: &Connection, internal_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM IDENTITY_PROVIDER_CONFIG WHERE IDENTITY_PROVIDER_ID=?1",
        &[SqlValue::Text(internal_id.to_string())],
    )
    .context("delete identity provider config")?;
    Ok(())
}

fn identity_provider_mapper_exists(conn: &Connection, mapper_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM IDENTITY_PROVIDER_MAPPER WHERE ID=?1",
            &[SqlValue::Text(mapper_id.to_string())],
        )
        .context("check identity provider mapper")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn insert_identity_provider_mapper(
    conn: &Connection,
    realm_id: &str,
    alias: &str,
    mapper_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO IDENTITY_PROVIDER_MAPPER (ID, IDP_ALIAS, IDP_MAPPER_NAME, NAME, REALM_ID) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            SqlValue::Text(mapper_id.to_string()),
            SqlValue::Text(alias.to_string()),
            string_value(value, "identityProviderMapper"),
            string_value(value, "name"),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("insert identity provider mapper")?;
    Ok(())
}

fn update_identity_provider_mapper_row(
    conn: &Connection,
    realm_id: &str,
    mapper_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE IDENTITY_PROVIDER_MAPPER SET IDP_ALIAS=?1, IDP_MAPPER_NAME=?2, NAME=?3 WHERE ID=?4 AND REALM_ID=?5",
        &[
            string_value(value, "identityProviderAlias"),
            string_value(value, "identityProviderMapper"),
            string_value(value, "name"),
            SqlValue::Text(mapper_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update identity provider mapper")?;
    Ok(())
}

fn load_identity_provider_mapper(
    conn: &Connection,
    realm_id: &str,
    mapper_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, IDP_ALIAS, IDP_MAPPER_NAME, NAME FROM IDENTITY_PROVIDER_MAPPER WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(mapper_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load identity provider mapper")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(
        &mut value,
        "identityProviderAlias",
        row.get::<&str>("IDP_ALIAS"),
    );
    set_opt_string(
        &mut value,
        "identityProviderMapper",
        row.get::<&str>("IDP_MAPPER_NAME"),
    );
    value["config"] = JsonValue::Object(load_identity_provider_mapper_config(
        conn, mapper_id,
    )?);
    Ok(Some(value))
}

fn load_identity_provider_mapper_config(
    conn: &Connection,
    mapper_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM IDP_MAPPER_CONFIG WHERE IDP_MAPPER_ID=?1",
            &[SqlValue::Text(mapper_id.to_string())],
        )
        .context("load identity provider mapper config")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn insert_identity_provider_mapper_config(
    conn: &Connection,
    mapper_id: &str,
    value: &JsonValue,
) -> Result<()> {
    let Some(config) = value.get("config").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in config {
        conn.execute(
            "INSERT INTO IDP_MAPPER_CONFIG (IDP_MAPPER_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(mapper_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert identity provider mapper config")?;
    }
    Ok(())
}

fn delete_identity_provider_mapper_config(conn: &Connection, mapper_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM IDP_MAPPER_CONFIG WHERE IDP_MAPPER_ID=?1",
        &[SqlValue::Text(mapper_id.to_string())],
    )
    .context("delete identity provider mapper config")?;
    Ok(())
}

fn delete_identity_provider_mappers(
    conn: &Connection,
    realm_id: &str,
    alias: &str,
) -> Result<()> {
    let rows = conn
        .execute(
            "SELECT ID FROM IDENTITY_PROVIDER_MAPPER WHERE REALM_ID=?1 AND IDP_ALIAS=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("load identity provider mappers")?;
    let mut mapper_ids = Vec::new();
    for row in rows.rows() {
        if let Some(mapper_id) = row.get::<&str>("ID") {
            mapper_ids.push(mapper_id.to_string());
        }
    }
    for mapper_id in mapper_ids {
        delete_identity_provider_mapper_config(conn, &mapper_id)?;
    }
    conn.execute(
        "DELETE FROM IDENTITY_PROVIDER_MAPPER WHERE REALM_ID=?1 AND IDP_ALIAS=?2",
        &[
            SqlValue::Text(realm_id.to_string()),
            SqlValue::Text(alias.to_string()),
        ],
    )
    .context("delete identity provider mappers")?;
    Ok(())
}

fn load_localizations(
    conn: &Connection,
    realm_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT LOCALE, TEXTS FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1",
            &[SqlValue::Text(realm_id.to_string())],
        )
        .context("load localizations")?;
    for row in rows.rows() {
        let Some(locale) = row.get::<&str>("LOCALE") else {
            continue;
        };
        let raw = row.get::<&str>("TEXTS").unwrap_or("");
        let parsed = serde_json::from_str::<JsonValue>(raw).ok();
        let value = parsed.unwrap_or_else(|| JsonValue::String(raw.to_string()));
        map.insert(locale.to_string(), value);
    }
    Ok(map)
}

fn load_localization_texts(
    conn: &Connection,
    realm_id: &str,
    locale: &str,
) -> Result<Option<serde_json::Map<String, JsonValue>>> {
    let rows = conn
        .execute(
            "SELECT TEXTS FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1 AND LOCALE=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(locale.to_string()),
            ],
        )
        .context("load localization texts")?;
    for row in rows.rows() {
        let raw = row.get::<&str>("TEXTS").unwrap_or("");
        if let Ok(value) = serde_json::from_str::<JsonValue>(raw) {
            if let Some(obj) = value.as_object() {
                return Ok(Some(obj.clone()));
            }
        }
        return Ok(Some(serde_json::Map::new()));
    }
    Ok(None)
}

fn localization_exists(conn: &Connection, realm_id: &str, locale: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT LOCALE FROM REALM_LOCALIZATIONS WHERE REALM_ID=?1 AND LOCALE=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(locale.to_string()),
            ],
        )
        .context("check localization exists")?;
    for _ in rows.rows() {
        return Ok(true);
    }
    Ok(false)
}

fn insert_role(
    conn: &Connection,
    realm_id: &str,
    role_id: &str,
    name: &str,
    value: &JsonValue,
) -> Result<()> {
    let client_role = value.get("clientRole").and_then(|v| v.as_bool()).unwrap_or(false);
    let client_ref = value
        .get("containerId")
        .and_then(|v| v.as_str())
        .map(|v| SqlValue::Text(v.to_string()))
        .unwrap_or(SqlValue::Null);
    conn.execute(
        "INSERT INTO KEYCLOAK_ROLE (CLIENT_ROLE, CLIENT_REALM_CONSTRAINT, ID, CLIENT, DESCRIPTION, NAME, REALM_ID) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[
            SqlValue::Integer(if client_role { 1 } else { 0 }),
            SqlValue::Text(realm_id.to_string()),
            SqlValue::Text(role_id.to_string()),
            client_ref,
            string_value(value, "description"),
            SqlValue::Text(name.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("insert role")?;
    Ok(())
}

fn update_role_row(
    conn: &Connection,
    realm_id: &str,
    role_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE KEYCLOAK_ROLE SET NAME=?1, DESCRIPTION=?2 WHERE ID=?3 AND REALM_ID=?4",
        &[
            string_value(value, "name"),
            string_value(value, "description"),
            SqlValue::Text(role_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update role")?;
    Ok(())
}

fn insert_role_attributes(conn: &Connection, role_id: &str, value: &JsonValue) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, val) in attrs {
        conn.execute(
            "INSERT INTO ROLE_ATTRIBUTE (ID, ROLE_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
            &[
                SqlValue::Text(generate_id("role-attr")),
                SqlValue::Text(role_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(val)),
            ],
        )
        .context("insert role attribute")?;
    }
    Ok(())
}

fn delete_role_attributes(conn: &Connection, role_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM ROLE_ATTRIBUTE WHERE ROLE_ID=?1",
        &[SqlValue::Text(role_id.to_string())],
    )
    .context("delete role attributes")?;
    Ok(())
}

fn delete_role_composite_rows(conn: &Connection, role_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM COMPOSITE_ROLE WHERE COMPOSITE=?1 OR CHILD_ROLE=?1",
        &[SqlValue::Text(role_id.to_string())],
    )
    .context("delete composite roles")?;
    Ok(())
}

fn delete_role_children(conn: &Connection, role_id: &str) -> Result<()> {
    delete_role_attributes(conn, role_id)?;
    delete_role_composite_rows(conn, role_id)?;
    Ok(())
}

fn role_id_by_name(conn: &Connection, realm_id: &str, name: &str) -> Result<Option<String>> {
    let rows = conn
        .execute(
            "SELECT ID FROM KEYCLOAK_ROLE WHERE REALM_ID=?1 AND NAME=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(name.to_string()),
            ],
        )
        .context("load role id")?;
    for row in rows.rows() {
        if let Some(id) = row.get::<&str>("ID") {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

fn role_name_exists(conn: &Connection, realm_id: &str, name: &str) -> Result<bool> {
    Ok(role_id_by_name(conn, realm_id, name)?.is_some())
}

fn role_id_exists(conn: &Connection, role_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM KEYCLOAK_ROLE WHERE ID=?1",
            &[SqlValue::Text(role_id.to_string())],
        )
        .context("check role id")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn role_is_composite(conn: &Connection, role_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT CHILD_ROLE FROM COMPOSITE_ROLE WHERE COMPOSITE=?1",
            &[SqlValue::Text(role_id.to_string())],
        )
        .context("check role composite")?;
    for _ in rows.rows() {
        return Ok(true);
    }
    Ok(false)
}

fn load_role_by_id(
    conn: &Connection,
    realm_id: &str,
    role_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, NAME, DESCRIPTION, CLIENT_ROLE, CLIENT, REALM_ID FROM KEYCLOAK_ROLE WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(role_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load role")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "description", row.get::<&str>("DESCRIPTION"));
    set_opt_bool(&mut value, "clientRole", row.get::<i64>("CLIENT_ROLE"));
    if let Some(client) = row.get::<&str>("CLIENT") {
        value["containerId"] = JsonValue::String(client.to_string());
    } else {
        value["containerId"] = JsonValue::String(realm_id.to_string());
    }
    value["composite"] = JsonValue::Bool(role_is_composite(conn, role_id)?);
    value["attributes"] = JsonValue::Object(load_role_attributes(conn, role_id)?);
    Ok(Some(value))
}

fn load_role_by_name(
    conn: &Connection,
    realm_id: &str,
    name: &str,
) -> Result<Option<JsonValue>> {
    let Some(role_id) = role_id_by_name(conn, realm_id, name)? else {
        return Ok(None);
    };
    load_role_by_id(conn, realm_id, &role_id)
}

fn load_role_attributes(
    conn: &Connection,
    role_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let mut map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM ROLE_ATTRIBUTE WHERE ROLE_ID=?1",
            &[SqlValue::Text(role_id.to_string())],
        )
        .context("load role attributes")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn role_id_from_value(
    conn: &Connection,
    realm_id: &str,
    value: &JsonValue,
) -> Result<String> {
    if let Some(id) = value.get("id").and_then(|v| v.as_str()) {
        return Ok(id.to_string());
    }
    if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
        if let Some(id) = role_id_by_name(conn, realm_id, name)? {
            return Ok(id);
        }
    }
    Err(anyhow!("role id or name is required"))
}

fn update_role_by_id_inner(
    conn: &Connection,
    realm_id: &str,
    role_id: &str,
    body: &[u8],
) -> Result<Response> {
    if load_role_by_id(conn, realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    let mut value = match parse_body(body) {
        Ok(value) => value,
        Err(err) => return json_response(400, json!({"error": err.to_string()})),
    };
    if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
        if let Some(existing) = role_id_by_name(conn, realm_id, name)? {
            if existing != role_id {
                return json_response(409, json!({"error": "role already exists"}));
            }
        }
    } else if let Some(current) = load_role_by_id(conn, realm_id, role_id)? {
        if let Some(current_name) = current.get("name").and_then(|v| v.as_str()) {
            value["name"] = JsonValue::String(current_name.to_string());
        }
    }

    execute_transaction(conn, |conn| {
        update_role_row(conn, realm_id, role_id, &value)?;
        if has_key(&value, "attributes") {
            delete_role_attributes(conn, role_id)?;
            insert_role_attributes(conn, role_id, &value)?;
        }
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn delete_role_by_id_inner(
    conn: &Connection,
    realm_id: &str,
    role_id: &str,
) -> Result<Response> {
    if load_role_by_id(conn, realm_id, role_id)?.is_none() {
        return json_response(404, json!({"error": "role not found"}));
    }
    execute_transaction(conn, |conn| {
        delete_role_children(conn, role_id)?;
        conn.execute(
            "DELETE FROM KEYCLOAK_ROLE WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(role_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("delete role")?;
        Ok(())
    })?;
    let mut builder = Response::builder();
    Ok(builder.status(204).body(Vec::new()).build())
}

fn user_id_exists(conn: &Connection, user_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM USER_ENTITY WHERE ID=?1",
            &[SqlValue::Text(user_id.to_string())],
        )
        .context("check user id")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn user_username_exists(conn: &Connection, realm_id: &str, username: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM USER_ENTITY WHERE REALM_ID=?1 AND USERNAME=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(username.to_string()),
            ],
        )
        .context("check username")?;
    let exists = rows.rows().next().is_some();
    Ok(exists)
}

fn insert_user(
    conn: &Connection,
    realm_id: &str,
    user_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO USER_ENTITY (ID, REALM_ID, USERNAME, EMAIL, FIRST_NAME, LAST_NAME, ENABLED, EMAIL_VERIFIED, CREATED_TIMESTAMP, NOT_BEFORE) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        &[
            SqlValue::Text(user_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
            string_value(value, "username"),
            string_value(value, "email"),
            string_value(value, "firstName"),
            string_value(value, "lastName"),
            bool_value(value, "enabled"),
            bool_value(value, "emailVerified"),
            int_value(value, "createdTimestamp"),
            int_value(value, "notBefore"),
        ],
    )
    .context("insert user")?;
    Ok(())
}

fn update_user_row(
    conn: &Connection,
    realm_id: &str,
    user_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE USER_ENTITY SET USERNAME=?1, EMAIL=?2, FIRST_NAME=?3, LAST_NAME=?4, ENABLED=?5, EMAIL_VERIFIED=?6, CREATED_TIMESTAMP=?7, NOT_BEFORE=?8 WHERE ID=?9 AND REALM_ID=?10",
        &[
            string_value(value, "username"),
            string_value(value, "email"),
            string_value(value, "firstName"),
            string_value(value, "lastName"),
            bool_value(value, "enabled"),
            bool_value(value, "emailVerified"),
            int_value(value, "createdTimestamp"),
            int_value(value, "notBefore"),
            SqlValue::Text(user_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update user")?;
    Ok(())
}

fn load_user_by_id(
    conn: &Connection,
    realm_id: &str,
    user_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, USERNAME, EMAIL, FIRST_NAME, LAST_NAME, ENABLED, EMAIL_VERIFIED, CREATED_TIMESTAMP, NOT_BEFORE FROM USER_ENTITY WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(user_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("load user")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "username", row.get::<&str>("USERNAME"));
    set_opt_string(&mut value, "email", row.get::<&str>("EMAIL"));
    set_opt_string(&mut value, "firstName", row.get::<&str>("FIRST_NAME"));
    set_opt_string(&mut value, "lastName", row.get::<&str>("LAST_NAME"));
    set_opt_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    set_opt_bool(&mut value, "emailVerified", row.get::<i64>("EMAIL_VERIFIED"));
    set_opt_int(&mut value, "createdTimestamp", row.get::<i64>("CREATED_TIMESTAMP"));
    set_opt_int(&mut value, "notBefore", row.get::<i64>("NOT_BEFORE"));
    value["attributes"] = JsonValue::Object(load_user_attributes(conn, user_id)?);
    value["requiredActions"] = JsonValue::Array(load_user_required_actions(conn, user_id)?);
    Ok(Some(value))
}

fn load_user_attributes(
    conn: &Connection,
    user_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let rows = conn
        .execute(
            "SELECT NAME, VALUE, LONG_VALUE FROM USER_ATTRIBUTE WHERE USER_ID=?1 ORDER BY NAME, ID",
            &[SqlValue::Text(user_id.to_string())],
        )
        .context("load user attributes")?;
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row
            .get::<&str>("VALUE")
            .or_else(|| row.get::<&str>("LONG_VALUE"))
            .unwrap_or("");
        grouped
            .entry(name.to_string())
            .or_default()
            .push(value.to_string());
    }
    let mut map = serde_json::Map::new();
    for (name, values) in grouped {
        let items = values
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        map.insert(name, JsonValue::Array(items));
    }
    Ok(map)
}

fn insert_user_attributes(conn: &Connection, user_id: &str, value: &JsonValue) -> Result<()> {
    let Some(attrs) = value.get("attributes").and_then(|v| v.as_object()) else {
        return Ok(());
    };
    for (name, attr_value) in attrs {
        match attr_value {
            JsonValue::Array(items) => {
                for item in items {
                    let entry = json_to_string(item);
                    if entry.is_empty() {
                        continue;
                    }
                    conn.execute(
                        "INSERT INTO USER_ATTRIBUTE (ID, USER_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
                        &[
                            SqlValue::Text(generate_id("user-attr")),
                            SqlValue::Text(user_id.to_string()),
                            SqlValue::Text(name.to_string()),
                            SqlValue::Text(entry),
                        ],
                    )
                    .context("insert user attribute")?;
                }
            }
            _ => {
                let entry = json_to_string(attr_value);
                if entry.is_empty() {
                    continue;
                }
                conn.execute(
                    "INSERT INTO USER_ATTRIBUTE (ID, USER_ID, NAME, VALUE) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqlValue::Text(generate_id("user-attr")),
                        SqlValue::Text(user_id.to_string()),
                        SqlValue::Text(name.to_string()),
                        SqlValue::Text(entry),
                    ],
                )
                .context("insert user attribute")?;
            }
        }
    }
    Ok(())
}

fn delete_user_attributes(conn: &Connection, user_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM USER_ATTRIBUTE WHERE USER_ID=?1",
        &[SqlValue::Text(user_id.to_string())],
    )
    .context("delete user attributes")?;
    Ok(())
}

fn load_user_required_actions(conn: &Connection, user_id: &str) -> Result<Vec<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT REQUIRED_ACTION FROM USER_REQUIRED_ACTION WHERE USER_ID=?1",
            &[SqlValue::Text(user_id.to_string())],
        )
        .context("load user required actions")?;
    let mut items = Vec::new();
    for row in rows.rows() {
        if let Some(action) = row.get::<&str>("REQUIRED_ACTION") {
            items.push(JsonValue::String(action.to_string()));
        }
    }
    Ok(items)
}

fn insert_user_required_actions(conn: &Connection, user_id: &str, value: &JsonValue) -> Result<()> {
    let Some(actions) = value.get("requiredActions").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for action in actions {
        if let Some(name) = action.as_str() {
            conn.execute(
                "INSERT INTO USER_REQUIRED_ACTION (USER_ID, REQUIRED_ACTION) VALUES (?1, ?2)",
                &[
                    SqlValue::Text(user_id.to_string()),
                    SqlValue::Text(name.to_string()),
                ],
            )
            .context("insert user required action")?;
        }
    }
    Ok(())
}

fn delete_user_required_actions(conn: &Connection, user_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM USER_REQUIRED_ACTION WHERE USER_ID=?1",
        &[SqlValue::Text(user_id.to_string())],
    )
    .context("delete user required actions")?;
    Ok(())
}

fn delete_user_children(conn: &Connection, user_id: &str) -> Result<()> {
    delete_user_attributes(conn, user_id)?;
    delete_user_required_actions(conn, user_id)?;
    conn.execute(
        "DELETE FROM USER_ROLE_MAPPING WHERE USER_ID=?1",
        &[SqlValue::Text(user_id.to_string())],
    )
    .context("delete user role mappings")?;
    conn.execute(
        "DELETE FROM USER_GROUP_MEMBERSHIP WHERE USER_ID=?1",
        &[SqlValue::Text(user_id.to_string())],
    )
    .context("delete user group membership")?;
    let rows = conn
        .execute(
            "SELECT ID FROM USER_CONSENT WHERE USER_ID=?1",
            &[SqlValue::Text(user_id.to_string())],
        )
        .context("load user consents")?;
    let mut consent_ids = Vec::new();
    for row in rows.rows() {
        if let Some(consent_id) = row.get::<&str>("ID") {
            consent_ids.push(consent_id.to_string());
        }
    }
    for consent_id in consent_ids {
        conn.execute(
            "DELETE FROM USER_CONSENT_CLIENT_SCOPE WHERE USER_CONSENT_ID=?1",
            &[SqlValue::Text(consent_id)],
        )
        .context("delete user consent scopes")?;
    }
    conn.execute(
        "DELETE FROM USER_CONSENT WHERE USER_ID=?1",
        &[SqlValue::Text(user_id.to_string())],
    )
    .context("delete user consents")?;
    Ok(())
}

fn organization_alias_exists(conn: &Connection, realm_id: &str, alias: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM ORG WHERE REALM_ID=?1 AND ALIAS=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("check organization alias")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn organization_id_exists(conn: &Connection, realm_id: &str, org_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM ORG WHERE REALM_ID=?1 AND ID=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(org_id.to_string()),
            ],
        )
        .context("check organization id")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insert_organization(
    conn: &Connection,
    realm_id: &str,
    org_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "INSERT INTO ORG (ENABLED, ID, ALIAS, DESCRIPTION, GROUP_ID, NAME, REALM_ID, REDIRECT_URL) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &[
            bool_value(value, "enabled"),
            SqlValue::Text(org_id.to_string()),
            string_value(value, "alias"),
            string_value(value, "description"),
            string_value(value, "groupId"),
            string_value(value, "name"),
            SqlValue::Text(realm_id.to_string()),
            string_value(value, "redirectUrl"),
        ],
    )
    .context("insert organization")?;
    Ok(())
}

fn update_organization_row(
    conn: &Connection,
    realm_id: &str,
    org_id: &str,
    value: &JsonValue,
) -> Result<()> {
    conn.execute(
        "UPDATE ORG SET ENABLED=?1, ALIAS=?2, DESCRIPTION=?3, GROUP_ID=?4, NAME=?5, REDIRECT_URL=?6 WHERE ID=?7 AND REALM_ID=?8",
        &[
            bool_value(value, "enabled"),
            string_value(value, "alias"),
            string_value(value, "description"),
            string_value(value, "groupId"),
            string_value(value, "name"),
            string_value(value, "redirectUrl"),
            SqlValue::Text(org_id.to_string()),
            SqlValue::Text(realm_id.to_string()),
        ],
    )
    .context("update organization")?;
    Ok(())
}

fn load_organization_by_id(
    conn: &Connection,
    realm_id: &str,
    org_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, DESCRIPTION, GROUP_ID, NAME, ENABLED, REDIRECT_URL FROM ORG WHERE REALM_ID=?1 AND ID=?2",
            &[
                SqlValue::Text(realm_id.to_string()),
                SqlValue::Text(org_id.to_string()),
            ],
        )
        .context("load organization")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "alias", row.get::<&str>("ALIAS"));
    set_opt_string(&mut value, "name", row.get::<&str>("NAME"));
    set_opt_string(&mut value, "description", row.get::<&str>("DESCRIPTION"));
    set_opt_string(&mut value, "groupId", row.get::<&str>("GROUP_ID"));
    set_opt_string(&mut value, "redirectUrl", row.get::<&str>("REDIRECT_URL"));
    set_opt_bool(&mut value, "enabled", row.get::<i64>("ENABLED"));
    Ok(Some(value))
}

fn load_organization_invitation(
    conn: &Connection,
    org_id: &str,
    invitation_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, EMAIL, FIRST_NAME, LAST_NAME, INVITE_LINK, CREATED_AT, EXPIRES_AT, ORGANIZATION_ID FROM ORG_INVITATION WHERE ORGANIZATION_ID=?1 AND ID=?2",
            &[
                SqlValue::Text(org_id.to_string()),
                SqlValue::Text(invitation_id.to_string()),
            ],
        )
        .context("load organization invitation")?;
    let Some(row) = rows.rows().next() else {
        return Ok(None);
    };
    let mut value = JsonValue::Object(serde_json::Map::new());
    set_opt_string(&mut value, "id", row.get::<&str>("ID"));
    set_opt_string(&mut value, "email", row.get::<&str>("EMAIL"));
    set_opt_string(&mut value, "firstName", row.get::<&str>("FIRST_NAME"));
    set_opt_string(&mut value, "lastName", row.get::<&str>("LAST_NAME"));
    set_opt_string(&mut value, "inviteLink", row.get::<&str>("INVITE_LINK"));
    set_opt_int(&mut value, "createdAt", row.get::<i64>("CREATED_AT"));
    set_opt_int(&mut value, "expiresAt", row.get::<i64>("EXPIRES_AT"));
    set_opt_string(&mut value, "organizationId", row.get::<&str>("ORGANIZATION_ID"));
    Ok(Some(value))
}

fn create_organization_invitation(
    conn: &Connection,
    org_id: &str,
    email: &str,
    value: &JsonValue,
) -> Result<()> {
    let invitation_id = value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| generate_id("invite"));
    let now = current_epoch_seconds();
    conn.execute(
        "INSERT INTO ORG_INVITATION (CREATED_AT, EXPIRES_AT, ID, INVITE_LINK, EMAIL, FIRST_NAME, LAST_NAME, ORGANIZATION_ID) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &[
            SqlValue::Integer(now),
            int_value(value, "expiresAt"),
            SqlValue::Text(invitation_id),
            string_value(value, "inviteLink"),
            SqlValue::Text(email.to_string()),
            string_value(value, "firstName"),
            string_value(value, "lastName"),
            SqlValue::Text(org_id.to_string()),
        ],
    )
    .context("insert organization invitation")?;
    Ok(())
}

fn json_to_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(val) => val.to_string(),
        JsonValue::Array(values) => values
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(","),
        _ => value.to_string(),
    }
}

fn bool_value(value: &JsonValue, key: &str) -> SqlValue {
    value
        .get(key)
        .and_then(|v| v.as_bool())
        .map(|v| SqlValue::Integer(if v { 1 } else { 0 }))
        .unwrap_or(SqlValue::Null)
}

fn string_value(value: &JsonValue, key: &str) -> SqlValue {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| SqlValue::Text(v.to_string()))
        .unwrap_or(SqlValue::Null)
}

fn int_value(value: &JsonValue, key: &str) -> SqlValue {
    value
        .get(key)
        .and_then(|v| v.as_i64())
        .map(SqlValue::Integer)
        .unwrap_or(SqlValue::Null)
}

fn bool_value_map(value: &serde_json::Map<String, JsonValue>, key: &str) -> SqlValue {
    value
        .get(key)
        .and_then(|v| v.as_bool())
        .map(|v| SqlValue::Integer(if v { 1 } else { 0 }))
        .unwrap_or(SqlValue::Null)
}

fn auth_flow_alias_exists(conn: &Connection, realm_id: &str, alias: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATION_FLOW WHERE ALIAS=?1 AND REALM_ID=?2",
            &[SqlValue::Text(alias.to_string()), SqlValue::Text(realm_id.to_string())],
        )
        .context("check flow alias")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn auth_flow_id_exists(conn: &Connection, flow_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATION_FLOW WHERE ID=?1",
            &[SqlValue::Text(flow_id.to_string())],
        )
        .context("check flow id")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn auth_flow_id_by_alias(conn: &Connection, realm: &str, alias: &str) -> Result<Option<String>> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return Ok(None);
    };
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATION_FLOW WHERE ALIAS=?1 AND REALM_ID=?2",
            &[SqlValue::Text(alias.to_string()), SqlValue::Text(realm_id)],
        )
        .context("load flow by alias")?;
    for row in rows.rows() {
        if let Some(id) = row.get::<&str>("ID") {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

fn load_auth_flow(
    conn: &Connection,
    realm_id: &str,
    flow_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, DESCRIPTION, PROVIDER_ID, TOP_LEVEL, BUILT_IN FROM AUTHENTICATION_FLOW WHERE ID=?1 AND REALM_ID=?2",
            &[SqlValue::Text(flow_id.to_string()), SqlValue::Text(realm_id.to_string())],
        )
        .context("load auth flow")?;
    for row in rows.rows() {
        let mut flow = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut flow, "id", row.get::<&str>("ID"));
        set_opt_string(&mut flow, "alias", row.get::<&str>("ALIAS"));
        set_opt_string(&mut flow, "description", row.get::<&str>("DESCRIPTION"));
        set_opt_string(&mut flow, "providerId", row.get::<&str>("PROVIDER_ID"));
        set_opt_bool(&mut flow, "topLevel", row.get::<i64>("TOP_LEVEL"));
        set_opt_bool(&mut flow, "builtIn", row.get::<i64>("BUILT_IN"));
        return Ok(Some(flow));
    }
    Ok(None)
}

fn load_auth_execution(
    conn: &Connection,
    execution_id: &str,
    flow_id: &str,
) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, REQUIREMENT, AUTHENTICATOR_FLOW, AUTHENTICATOR, AUTH_CONFIG, FLOW_ID, PRIORITY FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND FLOW_ID=?2",
            &[SqlValue::Text(execution_id.to_string()), SqlValue::Text(flow_id.to_string())],
        )
        .context("load auth execution")?;
    for row in rows.rows() {
        let mut exec = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut exec, "id", row.get::<&str>("ID"));
        set_opt_string(&mut exec, "requirement", requirement_name(row.get::<i64>("REQUIREMENT")));
        set_opt_bool(&mut exec, "authenticationFlow", row.get::<i64>("AUTHENTICATOR_FLOW"));
        set_opt_string(&mut exec, "providerId", row.get::<&str>("AUTHENTICATOR"));
        set_opt_string(&mut exec, "authenticationConfig", row.get::<&str>("AUTH_CONFIG"));
        set_opt_string(&mut exec, "flowId", row.get::<&str>("FLOW_ID"));
        set_opt_int(&mut exec, "priority", row.get::<i64>("PRIORITY"));
        set_opt_int(&mut exec, "index", row.get::<i64>("PRIORITY"));
        return Ok(Some(exec));
    }
    Ok(None)
}

fn auth_execution_exists(conn: &Connection, execution_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATION_EXECUTION WHERE ID=?1",
            &[SqlValue::Text(execution_id.to_string())],
        )
        .context("check auth execution")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn auth_execution_in_realm(
    conn: &Connection,
    execution_id: &str,
    realm_id: &str,
) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATION_EXECUTION WHERE ID=?1 AND REALM_ID=?2",
            &[
                SqlValue::Text(execution_id.to_string()),
                SqlValue::Text(realm_id.to_string()),
            ],
        )
        .context("check auth execution realm")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn auth_config_exists(conn: &Connection, config_id: &str) -> Result<bool> {
    let rows = conn
        .execute(
            "SELECT ID FROM AUTHENTICATOR_CONFIG WHERE ID=?1",
            &[SqlValue::Text(config_id.to_string())],
        )
        .context("check auth config")?;
    for row in rows.rows() {
        if row.get::<&str>("ID").is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn load_next_execution_priority(conn: &Connection, flow_id: &str) -> Result<i64> {
    let rows = conn
        .execute(
            "SELECT MAX(PRIORITY) as MAX_PRIORITY FROM AUTHENTICATION_EXECUTION WHERE FLOW_ID=?1",
            &[SqlValue::Text(flow_id.to_string())],
        )
        .context("load execution priority")?;
    for row in rows.rows() {
        let max_priority = row.get::<i64>("MAX_PRIORITY").unwrap_or(-1);
        return Ok(max_priority + 1);
    }
    Ok(0)
}

fn insert_auth_config_entries(
    conn: &Connection,
    config_id: &str,
    config: &serde_json::Map<String, JsonValue>,
) -> Result<()> {
    for (name, value) in config {
        conn.execute(
            "INSERT INTO AUTHENTICATOR_CONFIG_ENTRY (AUTHENTICATOR_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(config_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(value)),
            ],
        )
        .context("insert auth config entry")?;
    }
    Ok(())
}

fn load_auth_config(conn: &Connection, config_id: &str) -> Result<Option<JsonValue>> {
    let rows = conn
        .execute(
            "SELECT ID, ALIAS FROM AUTHENTICATOR_CONFIG WHERE ID=?1",
            &[SqlValue::Text(config_id.to_string())],
        )
        .context("load auth config")?;
    let mut base = None;
    for row in rows.rows() {
        let mut value = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut value, "id", row.get::<&str>("ID"));
        set_opt_string(&mut value, "alias", row.get::<&str>("ALIAS"));
        base = Some(value);
        break;
    }
    let Some(mut base) = base else {
        return Ok(None);
    };
    let mut config_map = serde_json::Map::new();
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM AUTHENTICATOR_CONFIG_ENTRY WHERE AUTHENTICATOR_ID=?1",
            &[SqlValue::Text(config_id.to_string())],
        )
        .context("load auth config entries")?;
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        config_map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    base["config"] = JsonValue::Object(config_map);
    Ok(Some(base))
}

fn load_required_action_row(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Option<(String, String, JsonValue)>> {
    let Some(realm_id) = realm_id_by_name(conn, realm)? else {
        return Ok(None);
    };
    let rows = conn
        .execute(
            "SELECT ID, ALIAS, NAME, PROVIDER_ID, ENABLED, DEFAULT_ACTION, PRIORITY FROM REQUIRED_ACTION_PROVIDER WHERE REALM_ID=?1 AND ALIAS=?2",
            &[
                SqlValue::Text(realm_id.clone()),
                SqlValue::Text(alias.to_string()),
            ],
        )
        .context("load required action")?;
    for row in rows.rows() {
        let Some(action_id) = row.get::<&str>("ID") else {
            continue;
        };
        let mut action = JsonValue::Object(serde_json::Map::new());
        set_opt_string(&mut action, "alias", row.get::<&str>("ALIAS"));
        set_opt_string(&mut action, "name", row.get::<&str>("NAME"));
        set_opt_string(&mut action, "providerId", row.get::<&str>("PROVIDER_ID"));
        set_opt_bool(&mut action, "enabled", row.get::<i64>("ENABLED"));
        set_opt_bool(&mut action, "defaultAction", row.get::<i64>("DEFAULT_ACTION"));
        set_opt_int(&mut action, "priority", row.get::<i64>("PRIORITY"));
        action["config"] = JsonValue::Object(load_required_action_config(conn, action_id)?);
        return Ok(Some((realm_id, action_id.to_string(), action)));
    }
    Ok(None)
}

fn load_required_action(
    conn: &Connection,
    realm: &str,
    alias: &str,
) -> Result<Option<JsonValue>> {
    Ok(load_required_action_row(conn, realm, alias)?.map(|(_, _, action)| action))
}

fn load_required_action_config(
    conn: &Connection,
    action_id: &str,
) -> Result<serde_json::Map<String, JsonValue>> {
    let rows = conn
        .execute(
            "SELECT NAME, VALUE FROM REQUIRED_ACTION_CONFIG WHERE REQUIRED_ACTION_ID=?1",
            &[SqlValue::Text(action_id.to_string())],
        )
        .context("load required action config")?;
    let mut map = serde_json::Map::new();
    for row in rows.rows() {
        let Some(name) = row.get::<&str>("NAME") else {
            continue;
        };
        let value = row.get::<&str>("VALUE").unwrap_or("");
        map.insert(name.to_string(), JsonValue::String(value.to_string()));
    }
    Ok(map)
}

fn insert_required_action_config(
    conn: &Connection,
    action_id: &str,
    config: &serde_json::Map<String, JsonValue>,
) -> Result<()> {
    for (name, value) in config {
        conn.execute(
            "INSERT INTO REQUIRED_ACTION_CONFIG (REQUIRED_ACTION_ID, NAME, VALUE) VALUES (?1, ?2, ?3)",
            &[
                SqlValue::Text(action_id.to_string()),
                SqlValue::Text(name.to_string()),
                SqlValue::Text(json_to_string(value)),
            ],
        )
        .context("insert required action config")?;
    }
    Ok(())
}

fn delete_required_action_config_entries(conn: &Connection, action_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM REQUIRED_ACTION_CONFIG WHERE REQUIRED_ACTION_ID=?1",
        &[SqlValue::Text(action_id.to_string())],
    )
    .context("delete required action config")?;
    Ok(())
}

fn requirement_name(value: Option<i64>) -> Option<&'static str> {
    match value {
        Some(0) => Some("REQUIRED"),
        Some(1) => Some("ALTERNATIVE"),
        Some(2) => Some("DISABLED"),
        Some(3) => Some("CONDITIONAL"),
        _ => None,
    }
}

fn requirement_to_int(value: Option<&str>) -> Option<i64> {
    match value.map(|v| v.to_ascii_uppercase()) {
        Some(v) if v == "REQUIRED" => Some(0),
        Some(v) if v == "ALTERNATIVE" => Some(1),
        Some(v) if v == "DISABLED" => Some(2),
        Some(v) if v == "CONDITIONAL" => Some(3),
        _ => None,
    }
}

fn current_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_id(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{now}")
}

fn string_value_map(value: &serde_json::Map<String, JsonValue>, key: &str) -> SqlValue {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| SqlValue::Text(v.to_string()))
        .unwrap_or(SqlValue::Null)
}

fn set_string(target: &mut JsonValue, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        target[key] = JsonValue::String(value.to_string());
    }
}

fn set_bool(target: &mut JsonValue, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target[key] = JsonValue::Bool(value != 0);
    }
}

fn set_int(target: &mut JsonValue, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target[key] = JsonValue::Number(value.into());
    }
}

fn method_to_str(method: &Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Connect => "CONNECT",
        Method::Options => "OPTIONS",
        Method::Trace => "TRACE",
        Method::Patch => "PATCH",
        _ => "UNKNOWN",
    }
}
