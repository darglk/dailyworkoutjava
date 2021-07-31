CREATE TABLE password_reset_token (
  password_reset_token_id VARCHAR(36) NOT NULL,
  app_user_id VARCHAR(36) NOT NULL,
  expiry_date TIMESTAMP NOT NULL,
  token VARCHAR(255) NOT NULL,
  PRIMARY KEY (password_reset_token_id),
  FOREIGN KEY (app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE
);

CREATE TABLE account_activation_token (
  account_activation_token_id VARCHAR(36) NOT NULL,
  app_user_id VARCHAR(36) NOT NULL,
  token VARCHAR(255) NOT NULL,
  PRIMARY KEY (account_activation_token_id),
  FOREIGN KEY (app_user_id) REFERENCES app_user(app_user_id) ON DELETE CASCADE
);