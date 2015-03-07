BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS propertystorage (
  id INTEGER PRIMARY KEY ASC,
  path TEXT,
  name TEXT,
  value TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS path_property ON propertystorage (path, name);

COMMIT;
