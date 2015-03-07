-- SabreDAV example SQL updated with proper schema relation constraints.

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS calendars (
  id INTEGER PRIMARY KEY ASC,
  principaluri TEXT,
  displayname TEXT,
  uri TEXT,
  synctoken INTEGER,
  description TEXT,
  calendarorder INTEGER,
  calendarcolor TEXT,
  timezone TEXT,
  components TEXT,
  transparent BOOL,
  FOREIGN KEY (principaluri) REFERENCES principals (uri) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS calendarobjects (
  id INTEGER PRIMARY KEY ASC,
  calendardata BLOB,
  uri TEXT,
  calendarid INTEGER,
  lastmodified INTEGER,
  etag TEXT,
  size INTEGER,
  componenttype TEXT,
  firstoccurence INTEGER,
  lastoccurence INTEGER,
  uid TEXT,
  FOREIGN KEY (calendarid) REFERENCES calendars (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS calendarchanges (
  id INTEGER PRIMARY KEY ASC,
  uri TEXT,
  synctoken INTEGER,
  calendarid INTEGER,
  operation INTEGER,
  FOREIGN KEY (calendarid) REFERENCES calendars (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS calendarid_synctoken ON calendarchanges (calendarid, synctoken);

CREATE TABLE IF NOT EXISTS calendarsubscriptions (
  id INTEGER PRIMARY KEY ASC,
  uri TEXT,
  principaluri TEXT,
  source TEXT,
  displayname TEXT,
  refreshrate TEXT,
  calendarorder INTEGER,
  calendarcolor TEXT,
  striptodos BOOL,
  stripalarms BOOL,
  stripattachments BOOL,
  lastmodified INT,
  FOREIGN KEY (principaluri) REFERENCES principals (uri) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schedulingobjects (
  id INTEGER PRIMARY KEY ASC,
  principaluri TEXT,
  calendardata BLOB,
  uri TEXT,
  lastmodified INTEGER,
  etag TEXT,
  size INTEGER,
  FOREIGN KEY (principaluri) REFERENCES principals (uri) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS principaluri_uri ON calendarsubscriptions (principaluri, uri);

COMMIT;
