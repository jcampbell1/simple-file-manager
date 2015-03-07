#!/usr/bin/env php
<?php

/*
 * Simple & Secure PHP File Manager.
 *
 * Quick & dirty database population script.
 * SQL templates are modified from SabreDAV.
 *
 * Copyright Kristian Garnét (garnetius).
 *
 * Liscense: MIT.
 */

require_once 'config.php';

$domain = $SFM['domain'] ? $SFM['domain'] : 'localhost';
$usedav = $SFM['enableDav'];
$db_sfm = $SFM['db'];
$db_dav_data = '/var/db/sqlite3/sabredav/data.db';
$db_dav_props = '/var/db/sqlite3/sabredav/properties.db';
$db_dav_locks = '/var/db/sqlite3/sabredav/locks.db';

define ('SQLITE_CONSTRAINT', 19);

if (count ($argv) < 2) exit (1);

$op = $argv[1];

if ($op != 'init')
{
	if (count ($argv) < 7) exit (1);

	$login = $argv[2];
	$pass = sha1 ($argv[3]);
	$home = $argv[4];
	$email = $argv[5] ? $argv[5] : 'noreply@'.$domain;
	$name = $argv[6] ? $argv[6] : 'Anonymous';
}

if ($op == 'init')
{
	if ($db_sfm)
	{
		$sqlite = new SQLite3 ($db_sfm) or die ("Couldn't open SQLite3 database `$db_sfm`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, login VARCHAR UNIQUE NOT NULL, pass VARCHAR NOT NULL, home VARCHAR UNIQUE NOT NULL);".
			"COMMIT;"
		)) sexit ($sqlite, 1);

		$sqlite->close();
	}

	if ($usedav)
	{
		$sqlite = new SQLite3 ($db_dav_data) or die ("Couldn't open SQLite3 database `$db_dav_data`.");

		if (!$sqlite->exec (file_get_contents ('sql/sqlite.principals.sql'))) sexit ($sqlite, 1);
		if (!$sqlite->exec (file_get_contents ('sql/sqlite.calendars.sql'))) sexit ($sqlite, 1);
		if (!$sqlite->exec (file_get_contents ('sql/sqlite.addressbooks.sql'))) sexit ($sqlite, 1);

		$sqlite->close();

		$sqlite = new SQLite3 ($db_dav_props) or die ("Couldn't open SQLite3 database `$db_dav_props`.");

		if (!$sqlite->exec (file_get_contents ('sql/sqlite.propertystorage.sql'))) sexit ($sqlite, 1);

		$sqlite->close();

		$sqlite = new SQLite3 ($db_dav_locks) or die ("Couldn't open SQLite3 database `$db_dav_locks`.");

		if (!$sqlite->exec (file_get_contents ('sql/sqlite.locks.sql'))) sexit ($sqlite, 1);

		$sqlite->close();
	}
}
else if ($op == 'add')
{
	if ($db_sfm)
	{
		$sqlite = new SQLite3 ($db_sfm) or die ("Couldn't open SQLite3 database `$db_sfm`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"INSERT OR IGNORE INTO user (login, pass, home) VALUES ('$login', '$pass', '$home');".
			"COMMIT;"
		) && $sqlite->lastErrorCode() != SQLITE_CONSTRAINT) sexit ($sqlite, 1);

		$sqlite->close();
	}

	if ($usedav)
	{
		$sqlite = new SQLite3 ($db_dav_data) or die ("Couldn't open SQLite3 database `$db_dav_data`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"INSERT OR IGNORE INTO principals (uri, email, displayname) VALUES ('principals/$login', '$email', '$name');".
				"INSERT OR IGNORE INTO principals (uri, email, displayname) VALUES ('principals/$login/calendar-proxy-read', null, null);".
				"INSERT OR IGNORE INTO principals (uri, email, displayname) VALUES ('principals/$login/calendar-proxy-write', null, null);".
			"COMMIT;"
		) && $sqlite->lastErrorCode() != SQLITE_CONSTRAINT) sexit ($sqlite, 1);

		$sqlite->close();
	}
}
else if ($op == 'remove')
{
	if ($db_sfm)
	{
		$sqlite = new SQLite3 ($db_sfm) or die ("Couldn't open SQLite3 database `$db_sfm`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"DELETE FROM user WHERE login = '$login';".
			"COMMIT;"
		)) sexit ($sqlite, 1);

		$sqlite->close();
	}

	if ($usedav)
	{
		$sqlite = new SQLite3 ($db_dav_data) or die ("Couldn't open SQLite3 database `$db_dav_data`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"DELETE FROM principals WHERE uri = 'principals/$login';".
				"DELETE FROM principals WHERE uri = 'principals/$login/calendar-proxy-read';".
				"DELETE FROM principals WHERE uri = 'principals/$login/calendar-proxy-write';".
			"COMMIT;"
		) && $sqlite->lastErrorCode() != SQLITE_CONSTRAINT) sexit ($sqlite, 1);

		$sqlite->close();
	}
}
else if ($op == 'modify')
{
	if ($db_sfm)
	{
		$sqlite = new SQLite3 ($db_sfm) or die ("Couldn't open SQLite3 database `$db_sfm`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"UPDATE user SET pass = '$pass', home = '$home' WHERE login = '$login';".
			"COMMIT;"
		)) sexit ($sqlite, 1);

		$sqlite->close();
	}

	if ($usedav)
	{
		$sqlite = new SQLite3 ($db_dav_data) or die ("Couldn't open SQLite3 database `$db_dav_data`.");

		if (!$sqlite->exec (
			"BEGIN TRANSACTION;".
				"UPDATE principals SET email = '$email', displayname = '$name' WHERE uri = 'principals/$login';".
			"COMMIT;"
		) && $sqlite->lastErrorCode() != SQLITE_CONSTRAINT) sexit ($sqlite, 1);

		$sqlite->close();
	}
}

function sexit ($sqlite, $code)
{
	echo $sqlite->lastErrorMsg()."\n";
	$sqlite->close();
	exit ($code);
}

exit (0);

?>
