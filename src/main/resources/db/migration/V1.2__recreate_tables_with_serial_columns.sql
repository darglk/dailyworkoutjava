DROP TABLE app_user_roles;
DROP TABLE app_user_authority;
DROP TABLE app_user;
DROP TABLE roles;
DROP TABLE authority;

CREATE TABLE authority (
  authority_id VARCHAR(36) NOT NULL,
  authority_name VARCHAR(30) NOT NULL UNIQUE,
  PRIMARY KEY (authority_id)
);

CREATE TABLE roles (
    role_id VARCHAR(36) NOT NULL,
    role_name VARCHAR(30) NOT NULL UNIQUE,
    PRIMARY KEY (role_id)
);

CREATE TABLE app_user (
  app_user_id  VARCHAR(36) NOT NULL,
  enabled BOOLEAN NOT NULL,
  password VARCHAR(255) NOT NULL,
  last_password_reset_date TIMESTAMP DEFAULT NOW(),
  email VARCHAR(255) NOT NULL,
  last_sign_in_ip VARCHAR(50) NULL,
  last_sign_in_date VARCHAR(50) NULL,
  PRIMARY KEY (app_user_id)
);

CREATE TABLE app_user_authority (
  app_user_id VARCHAR(36) NOT NULL,
  authority_id VARCHAR(36) NOT NULL,
  PRIMARY KEY(app_user_id, authority_id),
  FOREIGN KEY(app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE,
  FOREIGN KEY(authority_id) REFERENCES authority(authority_id) ON DELETE CASCADE
);

CREATE TABLE app_user_roles (
    app_user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    PRIMARY KEY(app_user_id, role_id),
    FOREIGN KEY(app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);