<?php

/*
 * Simple & Secure PHP File Manager.
 *
 * Copyright John Campbell (jcampbell1),
 *           Kristian Garnét (garnetius).
 *
 * Liscense: MIT.
 */

$root_dir = __DIR__; // Files root directory. Per-user home folders are appended to it.
$root_web = '.';     // Root directory location as seen from the browser.
$public = '';        // Public (sym)links directory. Set to 'public'
                     // to enable symlink shares (folder must exist under the $root_dir).

// Authentication & storage --------------------------------------------

$login = false; // Default user. Change to your 'username' to enable password-protected authentication.
$pass = '7c222fb2927d828af22f592134e8932480637c0d'; // php -r "echo sha1('12345678');" Don't forget to generate your own!

// Grab users from config.
$users = array();

if ($login !== false) $users = array(
	"$login" => array(
		'pass' => $pass,
		'home' => ''
	),
);

$db = ''; // Or use SQLite database (provide full path to DB, must be readable by PHP process).

// Cookies -------------------------------------------------------------

$cookie_session = '66880ed9-601e-4bd4-a5d6-689b125f7e27'; // Session cookie key.
$cookie_xsrf = 'bb3311df-e98e-4ae9-aae9-ba54635ef306';    // XSRF cookie key.
$cookie_path = null;
$cookie_domain = null;

// Banhammer -----------------------------------------------------------

$ban_login_attempts = 3;  // Ban after this number of (failed) login attempts.
$ban_attempt_timeout = 1; // Minutes before last attempted IP is removed from check list.
$ban_soft_timeout = 15;   // Minutes for which IP that failed all attampts will be banned for.
                          // There's no time limit on hard bans, reset them manually.

// Ban through system firewall (iptables/pf).
// Examples:
//   * Linux: `iptables -A INPUT -s {} -j DROP`
//   * FreeBSD: `pfctl -t sfm -T add {}` (Table "sfm" must exist.)
$ban_hardcore_cmd = ''; // Ban command, {} is replaced with the offending IP address.
$ban_hardcore_log = ''; // Log of hardcore bans (IPs) to reset (or inspect) them later.

// Memcached daemon settings -------------------------------------------

$memcached_enable = false; // Install memcached, memcache PHP extension
                           // and set this to `true` to enable bruteforce shield.
$memcached_host = '127.0.0.1';
$memcached_port = 11211;
$memcached_prefix = 'sfm.';

// File management limits ----------------------------------------------

$max_exists_tries = 10; // Stop generating names for new files and folders
                        // after this number of attempts (if target still exists).

$max_copy_depth = 10;   // Traverse no deeper than this when copying a folder.
$max_copy_size = 1024 * 1024 * 100; // Copy no longer than these bytes when copying a folder.

// Zip folder download support requires Zip PHP extension.
$max_zip_depth = 10;    // Traverse no deeper than this when zipping a folder.
$max_zip_size = 1024 * 1024 * 100;  // Bail out if combined (uncompressed) files size
                                    // reaches this amount of bytes when zipping a folder.

$curl_verify_ssl = true; // Request valid SSL certificate from server for SSL-protected cURL transfers.
$curl_enable = false;    // Allow remote transfers using cURL. Requires cURL PHP extension.

$dav_enable = false;     // Enable WebDAV (SabreDAV) support. Only needed for db.php.

// Miscellanious -------------------------------------------------------

$force_https = false; // Prevent plain HTTP authentication.
$serverinfo = false;  // Allow server info (`phpinfo()`) response.

// Pluggable authentication API ----------------------------------------

global $SFM;
$SFM = array(
	'login' => $login,
	'pass' => $pass,
	'db' => $db,
	'root' => $root_dir,
	'domain' => $cookie_domain,
	'cookie' => $cookie_session, // Can be usable for session sharing.
	'banLoginAttempts' => $ban_login_attempts,
	'banAttemptTimeout' => $ban_attempt_timeout,
	'banSoftTimeout' => $ban_soft_timeout,
	'banHardcore' => $ban_hardcore,
	'banHardcoreCmd' => $ban_hardcore_cmd,
	'banHardcoreLog' => $ban_hardcore_log,
	'enableMemcached' => $memcached_enable,
	'memcachedHost' => $memcached_host,
	'memcachedPort' => $memcached_port,
	'memcachedPrefix' => $memcached_prefix,
	'enableDav' => $dav_enable,
	'httpsOnly' => $force_https
);

function sfm_memcached_connect (&$SFM) {
	if ($SFM['enableMemcached']) {
		$memcache = memcache_pconnect ($SFM['memcachedHost'], $SFM['memcachedPort'])
		  or die('Couldn\'t connect to memcached.');

		return $memcache;
	}

	return null;
}

function sfm_memcached_close ($memcache) {
	if (!is_null ($memcache)) $memcache->close();
}

function sfm_authenticate_attempts ($memcache, &$SFM) {
	if ($SFM['enableMemcached']) {
		$memcached_prefix = $SFM['memcachedPrefix'];
		$ban_login_attempts = $SFM['banLoginAttempts'];
		$ban_soft_timeout = $SFM['banSoftTimeout'];

		// Get the number of failed login attempts.
		$attempts = intval($memcache->get($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR']));

		// Softcore ban.
		if ($attempts >= $ban_login_attempts) {
			$memcache->replace($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR'], $ban_login_attempts, 0, $ban_soft_timeout * 15);
			$memcache->close();
			return false;
		}

		return $attempts;
	}

	return 0;
}

function sfm_authenticate_reset ($memcache, &$SFM, $attempts) {
	if (!$SFM['enableMemcached']) return;

	$memcached_prefix = $SFM['memcachedPrefix'];

	if ($attempts != 0) $memcache->delete($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR']);
}

function sfm_authenticate_failure ($memcache, &$SFM, $attempts) {
	if (!$SFM['enableMemcached']) return;

	$memcached_prefix = $SFM['memcachedPrefix'];
	$ban_login_attempts = $SFM['banLoginAttempts'];
	$ban_attempt_timeout = $SFM['banAttemptTimeout'];
	$ban_soft_timeout = $SFM['banSoftTimeout'];
	$ban_hardcore_cmd = $SFM['banHardcoreCmd'];
	$ban_hardcore_log = $SFM['banHardcoreLog'];

	if (!$attempts) {
		$attempts = 1;
		if (!$memcache->add($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR'], $attempts, 0, $ban_attempt_timeout * 60)) {
			$attempts = $memcache->increment($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR']);
		}
	}
	else $attempts = $memcache->increment($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR']);

	$memcache->close();

	if ($attempts >= $ban_login_attempts) {
		$memcache->replace($memcached_prefix.'ip.'.$_SERVER['REMOTE_ADDR'], $ban_login_attempts, 0, $ban_soft_timeout * 15);

		// Hardcore ban.
		if ($ban_hardcore_cmd) {
			@system(str_replace('{}', $_SERVER['REMOTE_ADDR'], $ban_hardcore_cmd));

			if ($ban_hardcore_log) {
				$fh = fopen($ban_hardcore_log, 'a+');

				if ($fh) {
					fwrite($fh, $_SERVER['REMOTE_ADDR'].'\n');
					fclose($fh);
				}
			}
		}
	}

	return $attempts;
}

function sfm_authenticate ($memcache, &$SFM, $l, $p) {
	$db = $SFM['db'];
	$login = $SFM['login'];
	$pass = $SFM['pass'];

	// Get the number of login attempts so far.
	$attempts = sfm_authenticate_attempts($memcache, $SFM);

	if ($attempts === false) {
		$SFM['ban'] = true;
		return false;
	}

	// Validate the login and password.
	if (strlen($l) > 16 || strlen($p) > 32) return false;
	if (!preg_match('/^[0-9A-Za-z]+$/', $l)) return false;

	$p = sha1($p);
	$t = bin2hex(openssl_random_pseudo_bytes(16));

	$auth = null;

	if (is_readable($db))	{
		$sqlite = new SQLite3($db, SQLITE3_OPEN_READONLY) or die('Couldn\'t connect to SQLite3.');
		$row = $sqlite->querySingle("SELECT home FROM user WHERE login = '$l' AND pass = '$p';", true);
		$sqlite->close();
		if ($row['home']) $auth = $row;
	}
	else if ($users[$l])
	{
		$user = $users[$l];
		if ($t.$p === $t.$user['pass']) $auth = array('home' => $user['home']);
	}
	else if ($l === $login && $t.$p === $t.$pass) $auth = array('home' => '');
	else if ($login === false || is_null($login)) $auth = array('home' => ''); // For WebDAV: accept anything.

	// Success: create the user session.
	if (!is_null($auth)) {

		$auth['session'] = $t;

		// Reset login attempts (since authentication was successfull).
		sfm_authenticate_reset ($memcache, $SFM, $attempts);

		return $auth;
	}

	// Failure: track the number of failed login attempts.
	else sfm_authenticate_failure ($memcache, $SFM, $attempts);

	return false;
}

?>
