CREATE TABLE oauth_client_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255)
);

CREATE TABLE oauth_client_details (
  client_id VARCHAR(255) NOT NULL,
  resource_ids VARCHAR(255) DEFAULT NULL,
  client_secret VARCHAR(255) DEFAULT NULL,
  scope VARCHAR(255) DEFAULT NULL,
  authorized_grant_types VARCHAR(255) DEFAULT NULL,
  web_server_redirect_uri VARCHAR(255) DEFAULT NULL,
  authorities VARCHAR(255) DEFAULT NULL,
  access_token_validity INTEGER DEFAULT NULL,
  refresh_token_validity INTEGER DEFAULT NULL,
  additional_information VARCHAR(255) DEFAULT NULL,
  autoapprove VARCHAR(255) DEFAULT NULL
);

CREATE TABLE oauth_access_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication BYTEA,
  refresh_token VARCHAR(255)
);

CREATE TABLE oauth_refresh_token(
  token_id VARCHAR(255),
  token BYTEA,
  authentication BYTEA
);

CREATE TABLE authority (
  authority_id SERIAL NOT NULL,
  authority_name VARCHAR(30) NOT NULL UNIQUE,
  PRIMARY KEY (authority_id)
);

CREATE TABLE roles (
    role_id SERIAL NOT NULL,
    role_name VARCHAR(30) NOT NULL UNIQUE,
    PRIMARY KEY (role_id)
);

CREATE TABLE app_user (
  app_user_id  SERIAL NOT NULL,
  enabled BOOLEAN NOT NULL,
  password VARCHAR(255) NOT NULL,
  last_password_reset_date TIMESTAMP DEFAULT NOW(),
  email VARCHAR(255) NOT NULL,
  last_sign_in_ip VARCHAR(50) NULL,
  last_sign_in_date VARCHAR(50) NULL,
  PRIMARY KEY (app_user_id)
);

CREATE TABLE app_user_authority (
  app_user_id BIGINT NOT NULL,
  authority_id BIGINT NOT NULL,
  PRIMARY KEY(app_user_id, authority_id),
  FOREIGN KEY(app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE,
  FOREIGN KEY(authority_id) REFERENCES authority(authority_id) ON DELETE CASCADE
);

CREATE TABLE app_user_roles (
    app_user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY(app_user_id, role_id),
    FOREIGN KEY(app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

CREATE TABLE oauth_code (
  code VARCHAR(255),
  authentication BYTEA
);

CREATE TABLE oauth_approvals (
    userId VARCHAR(255),
    clientId VARCHAR(255),
    scope VARCHAR(255),
    status VARCHAR(10),
    expiresAt TIMESTAMP(0),
    lastModifiedAt TIMESTAMP(0)
);