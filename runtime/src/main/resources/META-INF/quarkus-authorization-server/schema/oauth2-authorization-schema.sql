CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    user_code_value text DEFAULT NULL,
    user_code_issued_at timestamp DEFAULT NULL,
    user_code_expires_at timestamp DEFAULT NULL,
    user_code_metadata text DEFAULT NULL,
    device_code_value text DEFAULT NULL,
    device_code_issued_at timestamp DEFAULT NULL,
    device_code_expires_at timestamp DEFAULT NULL,
    device_code_metadata text DEFAULT NULL,
    CONSTRAINT pk_oauth2_authorization PRIMARY KEY (id),
    CONSTRAINT uk_oauth2_authorization_access_token UNIQUE (access_token_value),
    CONSTRAINT uk_oauth2_authorization_refresh_token UNIQUE (refresh_token_value)
);

CREATE INDEX idx_oauth2_authorization_registered_client
    ON oauth2_authorization (registered_client_id);
CREATE INDEX idx_oauth2_authorization_principal
    ON oauth2_authorization (principal_name);
CREATE INDEX idx_oauth2_authorization_state
    ON oauth2_authorization (state);
CREATE INDEX idx_oauth2_authorization_authorization_code
    ON oauth2_authorization (authorization_code_value);
CREATE INDEX idx_oauth2_authorization_oidc_id_token
    ON oauth2_authorization (oidc_id_token_value);
CREATE INDEX idx_oauth2_authorization_user_code
    ON oauth2_authorization (user_code_value);
CREATE INDEX idx_oauth2_authorization_device_code
    ON oauth2_authorization (device_code_value);
