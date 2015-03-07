-- This table is not needed and not used by SFM.

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY ASC,
  username TEXT UNIQUE,
  digesta1 TEXT
);

--INSERT INTO users (username, digesta1) VALUES ('admin', '87fd274b7b6c01e48d7c2f965da8ddf7');
