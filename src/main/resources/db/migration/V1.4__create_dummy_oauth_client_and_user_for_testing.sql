
INSERT INTO roles (role_id, role_name)  VALUES('5653f19a-f1ea-11eb-b051-6f835b7ac685', 'ROLE_ADMIN');
INSERT INTO roles (role_id, role_name) VALUES('62b78258-f1ea-11eb-b051-6f835b7ac685', 'ROLE_USER');
INSERT INTO authority(authority_id, authority_name) VALUES('792d2c4a-f1ea-11eb-b051-6f835b7ac685', 'READ_AUTHORITY');
INSERT INTO authority(authority_id, authority_name) VALUES('7fca235a-f1ea-11eb-b051-6f835b7ac685', 'WRITE_AUTHORITY');
INSERT INTO app_user (app_user_id, enabled, password, last_password_reset_date, email)
VALUES('87c455a8-f1ea-11eb-b051-6f835b7ac685', TRUE,'$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2', now(), 'oauth_admin@test.com');

INSERT INTO app_user_authority (app_user_id, authority_id) VALUES ('87c455a8-f1ea-11eb-b051-6f835b7ac685','792d2c4a-f1ea-11eb-b051-6f835b7ac685');
INSERT INTO app_user_roles (app_user_id, role_id) VALUES('87c455a8-f1ea-11eb-b051-6f835b7ac685', '5653f19a-f1ea-11eb-b051-6f835b7ac685');

INSERT INTO oauth_client_details VALUES('oauth_client_id','oauth_server_api', '$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2',
'read,write', 'refresh_token,password', 'http://127.0.0.1', 'ROLE_ADMIN,ROLE_USER', 7200, 14400, NULL, 'true');