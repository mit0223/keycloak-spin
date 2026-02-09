
    create table ADMIN_EVENT_ENTITY (
        ADMIN_EVENT_TIME bigint,
        ID varchar(36) not null,
        RESOURCE_TYPE varchar(64),
        AUTH_CLIENT_ID varchar(255),
        AUTH_REALM_ID varchar(255),
        AUTH_USER_ID varchar(255),
        DETAILS_JSON varchar(255),
        ERROR varchar(255),
        IP_ADDRESS varchar(255),
        OPERATION_TYPE varchar(255),
        REALM_ID varchar(255),
        REPRESENTATION varchar(255),
        RESOURCE_PATH varchar(255),
        primary key (ID)
    );

    create table ASSOCIATED_POLICY (
        ASSOCIATED_POLICY_ID varchar(36) not null unique,
        POLICY_ID varchar(36) not null,
        primary key (ASSOCIATED_POLICY_ID, POLICY_ID)
    );

    create table AUTHENTICATION_EXECUTION (
        AUTHENTICATOR_FLOW boolean,
        PRIORITY integer,
        REQUIREMENT tinyint check ((REQUIREMENT between 0 and 3)),
        FLOW_ID varchar(36),
        ID varchar(36) not null,
        REALM_ID varchar(36),
        AUTHENTICATOR varchar(255),
        AUTH_CONFIG varchar(255),
        AUTH_FLOW_ID varchar(255),
        primary key (ID)
    );

    create table AUTHENTICATION_FLOW (
        BUILT_IN boolean,
        TOP_LEVEL boolean,
        ID varchar(36) not null,
        REALM_ID varchar(36),
        ALIAS varchar(255),
        DESCRIPTION varchar(255),
        PROVIDER_ID varchar(255),
        primary key (ID)
    );

    create table AUTHENTICATOR_CONFIG (
        ID varchar(36) not null,
        REALM_ID varchar(36),
        ALIAS varchar(255),
        primary key (ID)
    );

    create table AUTHENTICATOR_CONFIG_ENTRY (
        AUTHENTICATOR_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (AUTHENTICATOR_ID, NAME)
    );

    create table BROKER_LINK (
        BROKER_USERNAME varchar(255),
        BROKER_USER_ID varchar(255),
        IDENTITY_PROVIDER varchar(255) not null,
        REALM_ID varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        TOKEN varchar(255),
        USER_ID varchar(255) not null,
        primary key (IDENTITY_PROVIDER, USER_ID)
    );

    create table CLIENT (
        ALWAYS_DISPLAY_IN_CONSOLE boolean,
        BEARER_ONLY boolean,
        CONSENT_REQUIRED boolean,
        DIRECT_ACCESS_GRANTS_ENABLED boolean,
        ENABLED boolean,
        FRONTCHANNEL_LOGOUT boolean,
        FULL_SCOPE_ALLOWED boolean,
        IMPLICIT_FLOW_ENABLED boolean,
        NODE_REREG_TIMEOUT integer,
        NOT_BEFORE integer,
        PUBLIC_CLIENT boolean,
        SERVICE_ACCOUNTS_ENABLED boolean,
        STANDARD_FLOW_ENABLED boolean,
        SURROGATE_AUTH_REQUIRED boolean,
        ID varchar(36) not null,
        BASE_URL varchar(255),
        CLIENT_AUTHENTICATOR_TYPE varchar(255),
        CLIENT_ID varchar(255),
        DESCRIPTION varchar(255),
        MANAGEMENT_URL varchar(255),
        NAME varchar(255),
        PROTOCOL varchar(255),
        REALM_ID varchar(255),
        REGISTRATION_TOKEN varchar(255),
        ROOT_URL varchar(255),
        SECRET varchar(255),
        primary key (ID)
    );

    create table CLIENT_ATTRIBUTES (
        CLIENT_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (CLIENT_ID, NAME)
    );

    create table CLIENT_AUTH_FLOW_BINDINGS (
        CLIENT_ID varchar(36) not null,
        FLOW_ID varchar(4000),
        BINDING_NAME varchar(255) not null,
        primary key (CLIENT_ID, BINDING_NAME)
    );

    create table CLIENT_INITIAL_ACCESS (
        COUNT integer,
        EXPIRATION integer,
        REMAINING_COUNT integer,
        TIMESTAMP integer,
        ID varchar(36) not null,
        REALM_ID varchar(36),
        primary key (ID)
    );

    create table CLIENT_NODE_REGISTRATIONS (
        VALUE integer,
        CLIENT_ID varchar(36) not null,
        NAME varchar(255) not null,
        primary key (CLIENT_ID, NAME)
    );

    create table CLIENT_SCOPE (
        ID varchar(36) not null,
        DESCRIPTION varchar(255),
        NAME varchar(255),
        PROTOCOL varchar(255),
        REALM_ID varchar(255),
        primary key (ID)
    );

    create table CLIENT_SCOPE_ATTRIBUTES (
        SCOPE_ID varchar(36) not null,
        VALUE varchar(2048),
        NAME varchar(255) not null,
        primary key (SCOPE_ID, NAME)
    );

    create table CLIENT_SCOPE_CLIENT (
        DEFAULT_SCOPE boolean,
        CLIENT_ID varchar(255) not null,
        SCOPE_ID varchar(255) not null,
        primary key (CLIENT_ID, SCOPE_ID)
    );

    create table CLIENT_SCOPE_ROLE_MAPPING (
        ROLE_ID varchar(36) not null,
        SCOPE_ID varchar(36) not null,
        primary key (ROLE_ID, SCOPE_ID)
    );

    create table COMPONENT (
        ID varchar(36) not null,
        REALM_ID varchar(36),
        NAME varchar(255),
        PARENT_ID varchar(255),
        PROVIDER_ID varchar(255),
        PROVIDER_TYPE varchar(255),
        SUB_TYPE varchar(255),
        primary key (ID)
    );

    create table COMPONENT_CONFIG (
        COMPONENT_ID varchar(36),
        ID varchar(36) not null,
        NAME varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table COMPOSITE_ROLE (
        CHILD_ROLE varchar(36) not null,
        COMPOSITE varchar(36) not null,
        primary key (CHILD_ROLE, COMPOSITE)
    );

    create table CREDENTIAL (
        PRIORITY integer,
        VERSION integer,
        CREATED_DATE bigint,
        ID varchar(36) not null,
        USER_ID varchar(36),
        CREDENTIAL_DATA varchar(255),
        SALT blob,
        SECRET_DATA varchar(255),
        TYPE varchar(255),
        USER_LABEL varchar(255),
        primary key (ID)
    );

    create table DEFAULT_CLIENT_SCOPE (
        DEFAULT_SCOPE boolean,
        REALM_ID varchar(36) not null,
        SCOPE_ID varchar(255) not null,
        primary key (REALM_ID, SCOPE_ID)
    );

    create table EVENT_ENTITY (
        EVENT_TIME bigint,
        ID varchar(36) not null,
        DETAILS_JSON varchar(2550),
        CLIENT_ID varchar(255),
        DETAILS_JSON_LONG_VALUE varchar(255),
        ERROR varchar(255),
        IP_ADDRESS varchar(255),
        REALM_ID varchar(255),
        SESSION_ID varchar(255),
        TYPE varchar(255),
        USER_ID varchar(255),
        primary key (ID)
    );

    create table FED_USER_ATTRIBUTE (
        ID varchar(36) not null,
        LONG_VALUE varchar(255),
        LONG_VALUE_HASH blob,
        LONG_VALUE_HASH_LOWER_CASE blob,
        NAME varchar(255),
        REALM_ID varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        USER_ID varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table FED_USER_CONSENT (
        CREATED_DATE bigint,
        LAST_UPDATED_DATE bigint,
        ID varchar(36) not null,
        CLIENT_ID varchar(255),
        CLIENT_STORAGE_PROVIDER varchar(255),
        EXTERNAL_CLIENT_ID varchar(255),
        REALM_ID varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        USER_ID varchar(255),
        primary key (ID)
    );

    create table FED_USER_CONSENT_CL_SCOPE (
        USER_CONSENT_ID varchar(36) not null,
        SCOPE_ID varchar(255) not null,
        primary key (USER_CONSENT_ID, SCOPE_ID)
    );

    create table FED_USER_CREDENTIAL (
        PRIORITY integer,
        CREATED_DATE bigint,
        ID varchar(36) not null,
        CREDENTIAL_DATA varchar(255),
        REALM_ID varchar(255),
        SALT blob,
        SECRET_DATA varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        TYPE varchar(255),
        USER_ID varchar(255),
        USER_LABEL varchar(255),
        primary key (ID)
    );

    create table FED_USER_GROUP_MEMBERSHIP (
        GROUP_ID varchar(255) not null,
        REALM_ID varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        USER_ID varchar(255) not null,
        primary key (GROUP_ID, USER_ID)
    );

    create table FED_USER_REQUIRED_ACTION (
        REALM_ID varchar(255),
        REQUIRED_ACTION varchar(255) not null,
        STORAGE_PROVIDER_ID varchar(255),
        USER_ID varchar(255) not null,
        primary key (REQUIRED_ACTION, USER_ID)
    );

    create table FED_USER_ROLE_MAPPING (
        REALM_ID varchar(255),
        ROLE_ID varchar(255) not null,
        STORAGE_PROVIDER_ID varchar(255),
        USER_ID varchar(255) not null,
        primary key (ROLE_ID, USER_ID)
    );

    create table FEDERATED_IDENTITY (
        USER_ID varchar(36) not null,
        FEDERATED_USERNAME varchar(255),
        FEDERATED_USER_ID varchar(255),
        IDENTITY_PROVIDER varchar(255) not null,
        REALM_ID varchar(255),
        TOKEN varchar(255),
        primary key (USER_ID, IDENTITY_PROVIDER)
    );

    create table FEDERATED_USER (
        ID varchar(255) not null,
        REALM_ID varchar(255),
        STORAGE_PROVIDER_ID varchar(255),
        primary key (ID)
    );

    create table GROUP_ATTRIBUTE (
        GROUP_ID varchar(36),
        ID varchar(36) not null,
        NAME varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table GROUP_ROLE_MAPPING (
        GROUP_ID varchar(36) not null,
        ROLE_ID varchar(255) not null,
        primary key (GROUP_ID, ROLE_ID)
    );

    create table IDENTITY_PROVIDER (
        ADD_TOKEN_ROLE boolean,
        AUTHENTICATE_BY_DEFAULT boolean,
        ENABLED boolean,
        HIDE_ON_LOGIN boolean,
        LINK_ONLY boolean,
        STORE_TOKEN boolean,
        TRUST_EMAIL boolean,
        INTERNAL_ID varchar(36) not null,
        FIRST_BROKER_LOGIN_FLOW_ID varchar(255),
        ORGANIZATION_ID varchar(255),
        POST_BROKER_LOGIN_FLOW_ID varchar(255),
        PROVIDER_ALIAS varchar(255),
        PROVIDER_DISPLAY_NAME varchar(255),
        PROVIDER_ID varchar(255),
        REALM_ID varchar(255),
        primary key (INTERNAL_ID)
    );

    create table IDENTITY_PROVIDER_CONFIG (
        IDENTITY_PROVIDER_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE TEXT,
        primary key (IDENTITY_PROVIDER_ID, NAME)
    );

    create table IDENTITY_PROVIDER_MAPPER (
        ID varchar(36) not null,
        IDP_ALIAS varchar(255),
        IDP_MAPPER_NAME varchar(255),
        NAME varchar(255),
        REALM_ID varchar(255),
        primary key (ID)
    );

    create table IDP_MAPPER_CONFIG (
        IDP_MAPPER_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (IDP_MAPPER_ID, NAME)
    );

    create table KEYCLOAK_GROUP (
        TYPE integer,
        ID varchar(36) not null,
        ORG_ID varchar(36),
        DESCRIPTION varchar(255),
        NAME varchar(255),
        PARENT_GROUP varchar(255),
        REALM_ID varchar(255),
        primary key (ID)
    );

    create table KEYCLOAK_ROLE (
        CLIENT_ROLE boolean,
        CLIENT_REALM_CONSTRAINT varchar(36),
        ID varchar(36) not null,
        CLIENT varchar(255),
        DESCRIPTION varchar(255),
        NAME varchar(255),
        REALM_ID varchar(255),
        primary key (ID)
    );

    create table MIGRATION_MODEL (
        UPDATE_TIME bigint,
        ID varchar(36) not null,
        VERSION varchar(36),
        primary key (ID)
    );

    create table OFFLINE_CLIENT_SESSION (
        TIMESTAMP integer,
        VERSION integer,
        CLIENT_ID varchar(36) not null,
        CLIENT_STORAGE_PROVIDER varchar(36) not null,
        REALM_ID varchar(36),
        USER_SESSION_ID varchar(36) not null,
        DATA varchar(255),
        EXTERNAL_CLIENT_ID varchar(255) not null,
        OFFLINE_FLAG varchar(255) not null,
        primary key (CLIENT_ID, CLIENT_STORAGE_PROVIDER, USER_SESSION_ID, EXTERNAL_CLIENT_ID, OFFLINE_FLAG)
    );

    create table OFFLINE_USER_SESSION (
        CREATED_ON integer,
        LAST_SESSION_REFRESH integer,
        REMEMBER_ME boolean,
        VERSION integer,
        REALM_ID varchar(36),
        USER_SESSION_ID varchar(36) not null,
        BROKER_SESSION_ID varchar(255),
        DATA varchar(255),
        OFFLINE_FLAG varchar(255) not null,
        USER_ID varchar(255),
        primary key (USER_SESSION_ID, OFFLINE_FLAG)
    );

    create table ORG (
        ENABLED boolean,
        ID varchar(36) not null,
        ALIAS varchar(255),
        DESCRIPTION varchar(255),
        GROUP_ID varchar(255),
        NAME varchar(255),
        REALM_ID varchar(255),
        REDIRECT_URL varchar(255),
        primary key (ID)
    );

    create table ORG_DOMAIN (
        VERIFIED boolean,
        ID varchar(36) not null,
        ORG_ID varchar(36),
        NAME varchar(255),
        primary key (ID)
    );

    create table ORG_INVITATION (
        CREATED_AT integer not null,
        EXPIRES_AT integer,
        ID varchar(36) not null,
        INVITE_LINK varchar(2048),
        EMAIL varchar(255) not null,
        FIRST_NAME varchar(255),
        LAST_NAME varchar(255),
        ORGANIZATION_ID varchar(255) not null,
        primary key (ID)
    );

    create table POLICY_CONFIG (
        POLICY_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE TEXT,
        primary key (POLICY_ID, NAME)
    );

    create table PROTOCOL_MAPPER (
        CLIENT_ID varchar(36),
        CLIENT_SCOPE_ID varchar(36),
        ID varchar(36) not null,
        NAME varchar(255),
        PROTOCOL varchar(255),
        PROTOCOL_MAPPER_NAME varchar(255),
        primary key (ID)
    );

    create table PROTOCOL_MAPPER_CONFIG (
        PROTOCOL_MAPPER_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (PROTOCOL_MAPPER_ID, NAME)
    );

    create table REALM (
        ACCESS_CODE_LIFESPAN integer,
        ACCESS_TOKEN_LIFESPAN integer,
        ACCESS_TOKEN_LIFE_IMPLICIT integer,
        ADMIN_EVENTS_DETAILS_ENABLED boolean,
        ADMIN_EVENTS_ENABLED boolean,
        ALLOW_USER_MANAGED_ACCESS boolean,
        DUPLICATE_EMAILS_ALLOWED boolean,
        EDIT_USERNAME_ALLOWED boolean,
        ENABLED boolean,
        EVENTS_ENABLED boolean,
        INTERNATIONALIZATION_ENABLED boolean,
        LOGIN_LIFESPAN integer,
        LOGIN_WITH_EMAIL_ALLOWED boolean,
        NOT_BEFORE integer,
        OFFLINE_SESSION_IDLE_TIMEOUT integer,
        OTP_POLICY_COUNTER integer,
        OTP_POLICY_DIGITS integer,
        OTP_POLICY_PERIOD integer,
        OTP_POLICY_WINDOW integer,
        REFRESH_TOKEN_MAX_REUSE integer,
        REGISTRATION_ALLOWED boolean,
        REG_EMAIL_AS_USERNAME boolean,
        REMEMBER_ME boolean,
        RESET_PASSWORD_ALLOWED boolean,
        REVOKE_REFRESH_TOKEN boolean,
        SSO_IDLE_TIMEOUT integer,
        SSO_IDLE_TIMEOUT_REMEMBER_ME integer,
        SSO_MAX_LIFESPAN integer,
        SSO_MAX_LIFESPAN_REMEMBER_ME integer,
        USER_ACTION_LIFESPAN integer,
        VERIFY_EMAIL boolean,
        EVENTS_EXPIRATION bigint,
        ID varchar(36) not null,
        ACCOUNT_THEME varchar(255),
        ADMIN_THEME varchar(255),
        BROWSER_FLOW varchar(255),
        CLIENT_AUTH_FLOW varchar(255),
        DEFAULT_LOCALE varchar(255),
        DEFAULT_ROLE varchar(255),
        DIRECT_GRANT_FLOW varchar(255),
        DOCKER_AUTH_FLOW varchar(255),
        EMAIL_THEME varchar(255),
        LOGIN_THEME varchar(255),
        MASTER_ADMIN_CLIENT varchar(255),
        NAME varchar(255) unique,
        OTP_POLICY_ALG varchar(255),
        OTP_POLICY_TYPE varchar(255),
        PASSWORD_POLICY varchar(255),
        REGISTRATION_FLOW varchar(255),
        RESET_CREDENTIALS_FLOW varchar(255),
        SSL_REQUIRED varchar(255),
        primary key (ID)
    );

    create table REALM_ATTRIBUTE (
        REALM_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (REALM_ID, NAME)
    );

    create table REALM_DEFAULT_GROUPS (
        REALM_ID varchar(36) not null,
        GROUP_ID varchar(255)
    );

    create table REALM_ENABLED_EVENT_TYPES (
        REALM_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table REALM_EVENTS_LISTENERS (
        REALM_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table REALM_LOCALIZATIONS (
        REALM_ID varchar(36) not null,
        LOCALE varchar(255) not null,
        TEXTS varchar(255),
        primary key (REALM_ID, LOCALE)
    );

    create table REALM_REQUIRED_CREDENTIAL (
        INPUT boolean,
        SECRET boolean,
        REALM_ID varchar(36) not null,
        FORM_LABEL varchar(255),
        TYPE varchar(255) not null,
        primary key (REALM_ID, TYPE)
    );

    create table REALM_SMTP_CONFIG (
        REALM_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (REALM_ID, NAME)
    );

    create table REALM_SUPPORTED_LOCALES (
        REALM_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table REDIRECT_URIS (
        CLIENT_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table REQUIRED_ACTION_CONFIG (
        REQUIRED_ACTION_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (REQUIRED_ACTION_ID, NAME)
    );

    create table REQUIRED_ACTION_PROVIDER (
        DEFAULT_ACTION boolean,
        ENABLED boolean,
        PRIORITY integer,
        ID varchar(36) not null,
        REALM_ID varchar(36),
        ALIAS varchar(255),
        NAME varchar(255),
        PROVIDER_ID varchar(255),
        primary key (ID)
    );

    create table RESOURCE_ATTRIBUTE (
        ID varchar(36) not null,
        RESOURCE_ID varchar(36),
        NAME varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table RESOURCE_POLICY (
        POLICY_ID varchar(36) not null,
        RESOURCE_ID varchar(36) not null unique,
        primary key (POLICY_ID, RESOURCE_ID)
    );

    create table RESOURCE_SCOPE (
        RESOURCE_ID varchar(36) not null,
        SCOPE_ID varchar(36) not null unique
    );

    create table RESOURCE_SERVER (
        ALLOW_RS_REMOTE_MGMT boolean,
        DECISION_STRATEGY tinyint check ((DECISION_STRATEGY between 0 and 2)),
        POLICY_ENFORCE_MODE tinyint check ((POLICY_ENFORCE_MODE between 0 and 2)),
        ID varchar(36) not null,
        primary key (ID)
    );

    create table RESOURCE_SERVER_PERM_TICKET (
        CREATED_TIMESTAMP bigint,
        GRANTED_TIMESTAMP bigint,
        ID varchar(36) not null,
        POLICY_ID varchar(36),
        RESOURCE_ID varchar(36) not null,
        RESOURCE_SERVER_ID varchar(36) not null,
        SCOPE_ID varchar(36),
        OWNER varchar(255),
        REQUESTER varchar(255),
        primary key (ID)
    );

    create table RESOURCE_SERVER_POLICY (
        DECISION_STRATEGY tinyint check ((DECISION_STRATEGY between 0 and 2)),
        LOGIC tinyint check ((LOGIC between 0 and 1)),
        ID varchar(36) not null,
        RESOURCE_SERVER_ID varchar(36) not null,
        DESCRIPTION varchar(255),
        NAME varchar(255),
        OWNER varchar(255),
        TYPE varchar(255),
        primary key (ID)
    );

    create table RESOURCE_SERVER_RESOURCE (
        OWNER_MANAGED_ACCESS boolean,
        ID varchar(36) not null,
        DISPLAY_NAME varchar(255),
        ICON_URI varchar(255),
        NAME varchar(255),
        OWNER varchar(255),
        RESOURCE_SERVER_ID varchar(255),
        TYPE varchar(255),
        primary key (ID)
    );

    create table RESOURCE_SERVER_SCOPE (
        ID varchar(36) not null,
        RESOURCE_SERVER_ID varchar(36) not null,
        DISPLAY_NAME varchar(255),
        ICON_URI varchar(255),
        NAME varchar(255),
        primary key (ID)
    );

    create table RESOURCE_URIS (
        RESOURCE_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table REVOKED_TOKEN (
        EXPIRE bigint,
        ID varchar(36) not null,
        primary key (ID)
    );

    create table ROLE_ATTRIBUTE (
        ID varchar(36) not null,
        ROLE_ID varchar(36),
        NAME varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table SCOPE_MAPPING (
        CLIENT_ID varchar(36) not null,
        ROLE_ID varchar(255)
    );

    create table SCOPE_POLICY (
        POLICY_ID varchar(36) not null,
        SCOPE_ID varchar(36) not null unique,
        primary key (POLICY_ID, SCOPE_ID)
    );

    create table SERVER_CONFIG (
        VERSION integer,
        SERVER_CONFIG_KEY varchar(255) not null,
        VALUE varchar(255),
        primary key (SERVER_CONFIG_KEY)
    );

    create table USER_ATTRIBUTE (
        ID varchar(36) not null,
        USER_ID varchar(36),
        LONG_VALUE varchar(255),
        LONG_VALUE_HASH blob,
        LONG_VALUE_HASH_LOWER_CASE blob,
        NAME varchar(255),
        VALUE varchar(255),
        primary key (ID)
    );

    create table USER_CONSENT (
        CREATED_DATE bigint,
        LAST_UPDATED_DATE bigint,
        ID varchar(36) not null,
        USER_ID varchar(36),
        CLIENT_ID varchar(255),
        CLIENT_STORAGE_PROVIDER varchar(255),
        EXTERNAL_CLIENT_ID varchar(255),
        primary key (ID)
    );

    create table USER_CONSENT_CLIENT_SCOPE (
        USER_CONSENT_ID varchar(36) not null,
        SCOPE_ID varchar(255) not null,
        primary key (USER_CONSENT_ID, SCOPE_ID)
    );

    create table USER_ENTITY (
        EMAIL_VERIFIED boolean,
        ENABLED boolean,
        NOT_BEFORE integer,
        CREATED_TIMESTAMP bigint,
        ID varchar(36) not null,
        EMAIL varchar(255),
        EMAIL_CONSTRAINT varchar(255),
        FEDERATION_LINK varchar(255),
        FIRST_NAME varchar(255),
        LAST_NAME varchar(255),
        REALM_ID varchar(255),
        SERVICE_ACCOUNT_CLIENT_LINK varchar(255),
        USERNAME varchar(255),
        primary key (ID)
    );

    create table USER_FEDERATION_CONFIG (
        USER_FEDERATION_PROVIDER_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (USER_FEDERATION_PROVIDER_ID, NAME)
    );

    create table USER_FEDERATION_MAPPER (
        FEDERATION_PROVIDER_ID varchar(36),
        ID varchar(36) not null,
        REALM_ID varchar(36),
        FEDERATION_MAPPER_TYPE varchar(255),
        NAME varchar(255),
        primary key (ID)
    );

    create table USER_FEDERATION_MAPPER_CONFIG (
        USER_FEDERATION_MAPPER_ID varchar(36) not null,
        NAME varchar(255) not null,
        VALUE varchar(255),
        primary key (USER_FEDERATION_MAPPER_ID, NAME)
    );

    create table USER_FEDERATION_PROVIDER (
        CHANGED_SYNC_PERIOD integer,
        FULL_SYNC_PERIOD integer,
        LAST_SYNC integer,
        PRIORITY integer,
        ID varchar(36) not null,
        REALM_ID varchar(36),
        DISPLAY_NAME varchar(255),
        PROVIDER_NAME varchar(255),
        primary key (ID)
    );

    create table USER_GROUP_MEMBERSHIP (
        USER_ID varchar(36) not null,
        GROUP_ID varchar(255) not null,
        MEMBERSHIP_TYPE varchar(255),
        primary key (USER_ID, GROUP_ID)
    );

    create table USER_REQUIRED_ACTION (
        USER_ID varchar(36) not null,
        REQUIRED_ACTION varchar(255) not null,
        primary key (USER_ID, REQUIRED_ACTION)
    );

    create table USER_ROLE_MAPPING (
        USER_ID varchar(36) not null,
        ROLE_ID varchar(255) not null,
        primary key (USER_ID, ROLE_ID)
    );

    create table WEB_ORIGINS (
        CLIENT_ID varchar(36) not null,
        VALUE varchar(255)
    );

    create table WORKFLOW_STATE (
        SCHEDULED_STEP_TIMESTAMP bigint,
        EXECUTION_ID varchar(255) not null,
        RESOURCE_ID varchar(255),
        RESOURCE_TYPE varchar(255),
        SCHEDULED_STEP_ID varchar(255),
        WORKFLOW_ID varchar(255),
        primary key (EXECUTION_ID)
    );
