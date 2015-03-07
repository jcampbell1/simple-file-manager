-- SabreDAV example SQL updated with proper schema relation constraints.

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS addressbooks (
  id INTEGER PRIMARY KEY ASC,
  principaluri TEXT,
  displayname TEXT,
  uri TEXT,
  description TEXT,
  synctoken INTEGER,
  FOREIGN KEY (principaluri) REFERENCES principals (uri) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cards (
  id INTEGER primary KEY ASC,
  addressbookid INTEGER,
  carddata BLOB,
  uri TEXT,
  lastmodified INTEGER,
  etag TEXT,
  size INTEGER,
  FOREIGN KEY (addressbookid) REFERENCES addressbooks (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS addressbookchanges (
  id INTEGER primary KEY ASC,
  uri TEXT,
  synctoken INTEGER,
  addressbookid INTEGER,
  operation INTEGER,
  FOREIGN KEY (addressbookid) REFERENCES addressbooks (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS addressbookid_synctoken ON addressbookchanges (addressbookid, synctoken);

COMMIT;
