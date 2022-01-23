
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS users (
    id varchar(128) NOT NULL,
    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at datetime DEFAULT NULL,
    screen_name varchar(128) NOT NULL COMMENT "ユーザー名",
    name varchar(128) NOT NULL COMMENT "氏名",
    url varchar(128) NOT NULL COMMENT "ユーザーURL",
    description varchar(128) COMMENT "説明",
    is_signed_in boolean NOT NULL COMMENT "サインインフラグ",
    PRIMARY KEY(id)
) ENGINE=InnoDB;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE users;
