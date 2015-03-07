-- SabreDAV example SQL updated with proper schema relation constraints.

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS principals (
  id INTEGER PRIMARY KEY ASC,
  uri TEXT UNIQUE NOT NULL,
  email TEXT,
  displayname TEXT,
  vcardurl TEXT
);

CREATE TABLE IF NOT EXISTS groupmembers (
  id INTEGER PRIMARY KEY ASC,
  principal_id INTEGER,
  member_id INTEGER,
  UNIQUE (principal_id, member_id),
  FOREIGN KEY (principal_id) REFERENCES principals (id) ON DELETE CASCADE
);

COMMIT;
