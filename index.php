<?php

/*
 * Simple & Secure PHP File Manager.
 *
 * Copyright John Campbell (jcampbell1),
 *           Kristian Garnét (garnetius).
 *
 * Liscense: MIT.
 */

require_once 'config.php';

// Connect to memcached.
$memcache = sfm_memcached_connect ($SFM);

// Check login credentials.
$session = $_COOKIE[$cookie_session];

// Check if session is valid.
if ($session) {
	$session = $memcache->get($memcached_prefix.'au.'.$session);

	if (!$session) {
		setcookie($cookie_session, '', time() - 3600, $cookie_path, $cookie_domain, $force_https, true);
		$session = false;
	}
	else {
		$items = explode(':', $session);
		$login = $items[0];
		$home = $items[1];
		$root_dir = ($home) ? $root_dir.DIRECTORY_SEPARATOR.$home : $root_dir;
		$root_web = ($home) ? $root_web.DIRECTORY_SEPARATOR.$home.DIRECTORY_SEPARATOR : $root_web.DIRECTORY_SEPARATOR;
	}
}

// No authentication?
if ($login === false || is_null($login))
{
	$login = 'public';
	$home = '';
	$root_dir = ($home) ? $root_dir.DIRECTORY_SEPARATOR.$home : $root_dir;
	$root_web = ($home) ? $root_web.DIRECTORY_SEPARATOR.$home.DIRECTORY_SEPARATOR : $root_web.DIRECTORY_SEPARATOR;
}

// Request authorisation.
else if (!$session) {

	// AJAX?
	if ($_GET['do'] || $_POST['do']) err(401, "Not authorised.");

	// Check if login & password are provided.
	if ($_POST['l'] && $_POST['p']) {

		$auth = sfm_authenticate ($memcache, $SFM, $_POST['l'], $_POST['p']);

		if ($auth !== false) {

			// Success: generate unique session id.
			$session = $auth['session'];

			// Register the session with memcached.
			if (!$memcache->add($memcached_prefix.'au.'.$session, $_POST['l'].':'.$auth['home'], 0, 3600)) {
				$memcache->close();
				exit;
			}

			sfm_memcached_close ($memcache);

			// Reload the page.
			setcookie($cookie_session, $session, time() + 3600, $cookie_path, $cookie_domain, $force_https, true);
			header('Location: ?');

			exit;
		}

		if ($SFM['ban']) {
			http_response_code(401);
			exit;
		}
	}
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<style>
body {text-align: center}
#ident, #pass, #auth {font-family: "Lucida Grande", "Segoe UI", "Ubuntu", "Helvetica Neue", "Helvetica", Arial, sans-serif; font-size: 1.5em; border: 1px #C0C0C0 solid; border-radius: 8px; color: #808080; margin: .5em; padding: .5em; outline: none}
#ident, #pass {width: 10em} #ident:focus, #pass:focus {border-color: #82CFFA; color: #000}
#auth {font-size: 1.25em; border-radius: 6px; background: none; cursor: pointer}
#auth:hover {background: #F4FAFF; border-color: #82CFFA; color: #000}
#form {position: absolute; top: 50%; left: 50%; margin-top: -8.5em; margin-left: -10em}
</style>
	</head><body>
		<form id="form" action="?" method="POST">
			<div><input id="ident" type="text" name="l" placeholder="Identifier"/></div>
			<div><input id="pass" type="password" name="p" placeholder="Password"/></div>
			<div><input id="auth" type="submit" value="Authenticate"/></div>
		</form>
	</body>
</html>
<?php
	http_response_code(401);
	exit;
}

// Close the session.
if ($_GET['do'] == 'logout' && $session) {
	$memcache->delete($memcached_prefix.'au.'.$session);
	sfm_memcached_close ($memcache);

	// Remove cookies and reload the page.
	setcookie($cookie_session, '', time() - 3600, $cookie_path, $cookie_domain, $force_https, true);
	setcookie($cookie_xsrf, '', time() - 3600, $cookie_path, $cookie_domain, $force_https, true);
	header('Location: ?');

	exit;
}

// Close memcached socket (no effect if connection is persistent).
sfm_memcached_close ($memcache);

// Must be in UTF-8 or `basename` doesn't work.
@setlocale(LC_ALL, 'en_US.UTF-8');

// Validate the file name and the XSRF token.
$file = $_REQUEST['file'];
$fullpath = $root_dir.DIRECTORY_SEPARATOR.$file;
$tmp = '';

if (!is_link($fullpath)) {
	$tmp = realpath($fullpath);
	if ($tmp === false) err(404, 'File or directory "'.$_REQUEST['file'].'" not found.');
	if (strpos($tmp.DIRECTORY_SEPARATOR, $root_dir.DIRECTORY_SEPARATOR) !== 0) err(403, 'Invalid name.');
}
else {
	if (strpos($fullpath.DIRECTORY_SEPARATOR, $root_dir.DIRECTORY_SEPARATOR) !== 0) err(403, 'Invalid name.');
}

if ($file == basename(__FILE__) || $tmp == __FILE__) err(403, 'Invalid name.');

if (!$_COOKIE[$cookie_xsrf]) setcookie($cookie_xsrf, bin2hex(openssl_random_pseudo_bytes(16)), null, $cookie_path, $cookie_domain, $force_https, false);

if ($_POST) if ($_COOKIE[$cookie_xsrf] !== $_POST['xsrf'] || !$_POST['xsrf']) err(403, 'XSRF failure.');

$file = $file ? (($tmp == $root_dir) ? $root_dir : $root_dir.DIRECTORY_SEPARATOR.$file) : $root_dir;

// List files and directories.
if ($_GET['do'] == 'list') {
	if (is_dir($file)) {
		$directory = $file;
		$result = array();
		$files = array_diff(scandir($directory), array('.', '..'));

		foreach ($files as $entry) if ($entry !== basename(__FILE__)) {
			$i = $directory.DIRECTORY_SEPARATOR.$entry;
			$stat = @stat($i);
			$is_link = is_link($i);
			$is_dir = is_dir($i);

			$row = array(
				'mtime' => $stat['mtime'],
				'size' => $stat['size'],
				'name' => basename($i),
				'path' => substr($i, strlen($root_dir) + 1),
				'is_dir' => $is_dir,
				'is_deleteable' => (!$is_dir && is_writable($directory)) ||
				                   ($is_dir && is_writable($directory) && is_recursively_deleteable($i)),
				'is_readable' => is_readable($i),
				'is_writable' => is_writable($i),
				'is_executable' => is_executable($i),
				'is_link' => $is_link,
				'is_synced' => ($is_dir && file_exists($i.DIRECTORY_SEPARATOR.'.stfolder'))
			);

			if ($is_link) {
				$target = readlink($i);
				$fulltarget = '';
				if ($target !== false) {
					$fulltarget = ($target[0] == '/') ? $target : realpath(dirname($i).DIRECTORY_SEPARATOR.$target);
				}
				$row['link_target'] = ($target === false) ? '' : substr($fulltarget, strlen($root_dir) + 1);
				$row['link_broken'] = ($target === false) ? true : (file_exists($fulltarget) ? false : true);
			}

			array_push ($result, $row);
		}
	} else err(412, '"'.$_REQUEST['file'].'" is not a directory.');

	echo json_encode(array('success' => true,
	                       'is_writable' => is_writable($file),
	                       'results' => $result));

	exit;

// Search for files and folders.
} elseif ($_GET['do'] == 'search' && $_GET['name']) {

	if (!is_dir($file)) exit;

	$name = $_GET['name'];
	if (has_dots($name)) err(403, "Invalid name.");

	$result = array();
	recursive_search($result, $name, $file);

	echo json_encode(array('success' => true,
	                       'is_writable' => false,
	                       'results' => $result));

	exit;

// Remove file or directory tree.
} elseif ($_POST['do'] == 'delete') {

	rmrf($file);
	exit;

// Create new directory.
} elseif ($_POST['do'] == 'mkdir' && $_POST['name']) {

	$name = $_POST['name'];
	if (has_dots($name)) err(403, 'Invalid name.');

	if (!@mkdir($file.DIRECTORY_SEPARATOR.$_POST['name'])) err(500, 'Couldn\'t create directory "'.$_POST['name'].'".');

	exit;

// Create new file.
} elseif ($_POST['do'] == 'new' && $_POST['name']) {

	$name = $_POST['name'];
	if (has_dots($name)) err(403, 'Invalid name.');

	if (!@touch($file.DIRECTORY_SEPARATOR.$_POST['name'])) err(500, 'Couldn\'t create file "'.$_POST['name'].'".');

	exit;

// Upload new file.
} elseif ($_POST['do'] == 'upload') {

	var_dump($_POST);
	var_dump($_FILES);
	var_dump($_FILES['file_data']['tmp_name']);
	var_dump(move_uploaded_file($_FILES['file_data']['tmp_name'], $file.DIRECTORY_SEPARATOR.$_FILES['file_data']['name']));

	exit;

// Upload remote file using cURL.
} elseif ($curl_enable && $_POST['do'] == 'fetch' && $_POST['url']) {

	set_time_limit(0);

	$url = $_POST['url'];
	$fetched = $file.DIRECTORY_SEPARATOR.basename($url);
	if (file_exists($fetched)) err(412, 'Target "'.basename($url).'" already exists.');

	$fh = @fopen($fetched, 'w+');
	if (!$fh) err(500, 'Couldn\'t open file "'.basename($url).'" for writing.');

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_FILE, $fh);
	curl_setopt($ch, CURLOPT_HEADER, false);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
	curl_setopt($ch, CURLOPT_FORBID_REUSE, true);
	curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
	curl_setopt($ch, CURLOPT_TCP_NODELAY, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $curl_verify_ssl);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
	curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 30);
	curl_setopt($ch, CURLOPT_LOW_SPEED_LIMIT, 1024 * 16);
	curl_setopt($ch, CURLOPT_LOW_SPEED_TIME, 30);
	curl_setopt($ch, CURLOPT_LOW_SPEED_TIME, 30);
	curl_setopt($ch, CURLOPT_MAXCONNECTS, 1);
	curl_setopt($ch, CURLOPT_MAXREDIRS, 8);
	curl_exec($ch);
	curl_close($ch);
	fclose($fh);

	exit;

// Download the file (stream to browser).
} elseif ($_GET['do'] == 'download') {

	$filename = basename($file);

	// Download the folder as Zip archive.
	if (is_dir ($file) && $max_zip_depth) {
		$zip = new ZipArchive;
		$zipname = $filename.'.zip';
		$zipuniq = uniqid().'.zip';
		$zipfile = $file.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.$zipuniq;

		if (!$zip->open($zipfile, ZipArchive::CREATE | ZipArchive::EXCL)) err(500, 'Couldn\'t create Zip file "'.$zipuniq.'".');

		// Create recursive directory iterator.
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator ($file),
			RecursiveIteratorIterator::LEAVES_ONLY
		);

		$zip_size = 0;

		foreach ($files as $name => $f) {
			if ($files->getDepth() >= $max_zip_depth) {
				@unlink($zipfile);
				err(500, 'The folder is too big (maximum allowed recursion depth has been reached).');
			}

			$filePath = $f->getRealPath();

			if (!is_dir ($filePath)) {
				$zip_size += filesize($filePath);

				if ($zip_size >= $max_zip_size) {
					@unlink($zipfile);
					err(500, 'The folder is too big (maximum Zip file size has been reached).');
				}

				$zip->addFile($filePath, substr($filePath, strlen($file) - strlen($filename)));
			}
		}

		// Zip archive will be created only after closing the object.
		$zip->close();

		header('Content-Type: application/zip');
		header('Content-Length: '.filesize($zipfile));
		header(sprintf('Content-Disposition: attachment; filename=%s',
		  strpos('MSIE', $_SERVER['HTTP_REFERER']) ? rawurlencode($zipname) : "\"$zipname\""));

		ob_flush();

		$fin = fopen($zipfile, 'r');
		@unlink($zipfile);

		if ($fin === false) err(500, "Input error.");

		$fout = fopen('php://output', 'w');

		if ($fout == false) {
			fclose ($fin);
			err(500, "Output error.");
		}

		while (!feof($fin)) {
			$buff = fread($fin, 4096);

			if ($buff === false) {
				fclose ($fin);
				fclose ($fout);
				err(500, "Read error.");
			}

			if (fwrite($fout, $buff) === false) {
				fclose ($fin);
				fclose ($fout);
				err(500, "Write error.");
			}
		}

		fclose ($fin);
		fclose ($fout);
	}
	else {
		header('Content-Type: '.mime_content_type($file));
		header('Content-Length: '.filesize($file));
		header(sprintf('Content-Disposition: attachment; filename=%s',
		  strpos('MSIE', $_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\""));

		ob_flush();
		readfile($file);
	}

	exit;

// Create public file link (symlink).
} elseif ($public && $_POST['do'] == 'link' && $_POST['name']) {

	if ($file == $root_dir) err(500, "Cannot symlink root folder.");

	$name = $_POST['name'];
	if (has_dots ($name)) err(403, 'Invalid name.');

	// Calculate relative path for the symlink.
	$link = $root_dir.DIRECTORY_SEPARATOR.$public.DIRECTORY_SEPARATOR.$_POST['name'];
	$s = similartext($file, $link);
	$m = preg_replace('/\/+/g', '/', substr($link, $s));
	$c = substr_count($m, '/');
	$l = str_repeat('..'.DIRECTORY_SEPARATOR, $c + 1).substr($file, $s);

	if (!@symlink($l, $link)) err(500, 'Couldn\'t create public link "'.$public.DIRECTORY_SEPARATOR.$_POST['name'].'".');

	exit;

// Rename file or folder.
} elseif ($_POST['do'] == 'rename' && $_POST['name']) {

	if ($file == $root_dir) err(500, "Cannot rename or move root folder `$file`.");

	$name = $_POST['name'];
	if (has_dots ($name)) err(403, 'Invalid name.');

	if (!@rename($file, $root_dir.DIRECTORY_SEPARATOR.$_POST['name'])) err(500, 'Couldn\'t rename "'.$_REQUEST['file'].'" to "'.$_POST['name'].'".');

	exit;

// Move file or folder.
} elseif (($_POST['do'] == 'move' || $_POST['do'] == 'copy') && $_POST['name']) {

	$target = $_POST['name'];

	if ($file == $root_dir || $target == DIRECTORY_SEPARATOR) err(500, "Cannot copy, move or replace root folder.");
	if (has_dots ($target)) err(403, 'Invalid target.');

	if ($_POST['do'] == 'copy') {
		$newname = $target;
		$try = 0;

		while (file_exists($root_dir.DIRECTORY_SEPARATOR.$newname)) {
			$try++;
			if ($try >= $max_exists_tries) err(412, 'Target "'.$target.'" alredy exists.');
			$newname = $target.'-'.$try;
		}

		$target = $newname;

		// Recursively copy entire folder.
		if (is_dir($file) && $max_copy_depth)
		{
			$target = $root_dir.DIRECTORY_SEPARATOR.$target;

			if (!@mkdir($target, 0755)) err(500, 'Couldn\'t create "'.$_POST['name'].'".');

			$copy_size = 0;

			foreach ($iterator = new RecursiveIteratorIterator(
			  new RecursiveDirectoryIterator($file, RecursiveDirectoryIterator::SKIP_DOTS),
			  RecursiveIteratorIterator::SELF_FIRST) as $item
			) {
				if ($iterator->getDepth() >= $max_copy_depth) {
					err(500, 'The folder is too big (maximum allowed recursion depth has been reached).');
				}

				if ($item->isDir()) {
					if (!@mkdir($target.DIRECTORY_SEPARATOR.$iterator->getSubPathName())) err(500, 'Couldn\'t create "'.$_POST['name'].DIRECTORY_SEPARATOR.$iterator->getSubPathName().'".');
				} else {
					$copy_size += filesize ($item);

					if ($copy_size >= $max_copy_size) {
						err(500, 'The folder is too big (maximum combined size has been reached).');
					}

					if (!@copy($item, $target.DIRECTORY_SEPARATOR.$iterator->getSubPathName())) err(500, 'Couldn\'t copy "'.$_POST['file'].DIRECTORY_SEPARATOR.$iterator->getSubPathName().'".');
				}
			}
		}

		if (!@copy($file, $root_dir.DIRECTORY_SEPARATOR.$target)) err(500, 'Couldn\'t copy "'.$_POST['file'].'".');
	}
	else {
		if (!@rename($file, $root_dir.DIRECTORY_SEPARATOR.$target)) err(500, 'Couldn\'t move "'.$_POST['file'].'".');
	}

	exit;

// Show server info.
} elseif ($serverinfo && $_GET['do'] == 'phpinfo') {
	phpinfo();
	exit;
}

function rmrf($dir) {
	if (is_dir($dir)) {
		$files = array_diff(scandir($dir), array('.', '..'));
		foreach ($files as $file) rmrf("$dir/$file");
		@rmdir($dir);
	}
	else @unlink($dir);
}

function is_recursively_deleteable($d) {
	$stack = array($d);
	while ($dir = array_pop($stack)) {
		if (!is_readable($dir) || !is_writable($dir)) return false;
		$files = array_diff(scandir($dir), array('.', '..'));
		foreach ($files as $file) if (is_dir($file)) $stack[] = "$dir/$file";
	}
	return true;
}

function err($code, $msg) {
	echo json_encode(array('error' => array('code' => intval($code), 'msg' => $msg)));
	exit;
}

function as_bytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = array('g' => 1<<30, 'm' => 1<<20, 'k' => 1<<10);
	return intval($ini_v) * ($s[strtolower(substr($ini_v, -1))] ?: 1);
}

function has_dots($path) {
	$path = '.'.DIRECTORY_SEPARATOR.$path;
	if (DIRECTORY_SEPARATOR == '/') return (strpos($path, '/../') || strpos($path, '/./')) ? true : false;
	else return (strpos($path, '\\..\\') || strpos($path, '\\.\\')) ? true : false;
}

function recursive_search(&$result, $name, $root)
{
	global $root_dir;

	$files = array_diff(scandir($root), array('.', '..'));

	foreach ($files as $entry) if ($entry !== basename(__FILE__)) {
		$i = $root.DIRECTORY_SEPARATOR.$entry;
		$is_dir = is_dir($i);
		$is_readable = is_readable($i);

		if (strpos($entry, $name) !== false) {
			$stat = @stat($i);
			$is_link = is_link($i);

			$row = array(
				'mtime' => $stat['mtime'],
				'size' => $stat['size'],
				'name' => basename($i),
				'path' => substr($i, strlen($root_dir) + 1),
				'is_dir' => $is_dir,
				'is_deleteable' => false,
				'is_readable' => $is_readable,
				'is_writable' => is_writable($i),
				'is_executable' => is_executable($i),
				'is_link' => $is_link,
				'is_synced' => ($is_dir && file_exists($i.DIRECTORY_SEPARATOR.'.stfolder'))
			);

			if ($is_link) {
				$target = readlink($i);
				$fulltarget = '';
				if ($target !== false) {
					$fulltarget = ($target[0] == '/') ? $target : realpath(dirname($i).DIRECTORY_SEPARATOR.$target);
				}
				$row['link_target'] = ($target === false) ? '' : substr($fulltarget, strlen($root_dir) + 1);
				$row['link_broken'] = ($target === false) ? true : (file_exists($fulltarget) ? false : true);
			}

			array_push ($result, $row);
		}

		if ($is_dir && $is_readable) recursive_search($result, $name, $i);
	}
}

// similar_text is overkill and unusable for our purposes.
function similartext($s1, $s2)
{
	$i = 0;
	$l1 = strlen($s1);
	$l2 = strlen($s2);
	$l = ($l1 > $l2) ? $l1 : $l2;
	while ($i < $l && $s1[$i] == $s2[$i]) $i++;
	return $i;
}

$MAX_UPLOAD_SIZE = min(as_bytes(ini_get('post_max_size')), as_bytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<style>
body {font-family: "Lucida Grande", "Segoe UI", "Ubuntu", "Helvetica Neue", "Helvetica", Arial, sans-serif; font-size: 14px; width: 1024; padding: 1em; margin: 0; border: 0}
th {font-weight: normal; color: #1F75CC; background-color: #F0F8FF; padding: .5em 1em .5em .2em; text-align: left; cursor: pointer; user-select: none}
th .indicator {margin-left: 6px} th.col-permissions {width: 10%} th.col-name {width: 40%}
thead {border-top: 1px solid #82CFFA; border-bottom: 1px solid #82CFFA; border-left: 0; border-right: 0}
label {display: block; font-size: 11px; color: #555}
a, a:visited {color: #00C; text-decoration: none} a:hover {text-decoration: underline}
footer {font-size: 11px; color: #BBBBC5; padding: 4em 0 0; text-align: left} footer a, footer a:visited {color:#BBBBC5}
#logout {display: inline-block; float: left; padding-bottom: 32px} #search {display: inline-block; float: right}
#file_drop_target {width: 50%; padding: 12px 0; border: 4px dashed #CCC; font-size: 12px; color: #CCC; text-align: center; float: right; margin-right: 20px}
#file_drop_target.drag_over {border: 4px dashed #96C4EA; color: #96C4EA}
#upload_progress {padding: 4px 0} #upload_progress .error {color: #A00} #upload_progress > div {padding: 3px 0}
.progress_track {display: inline-block; width: 200px; height: 10px; border: 1px solid #333; margin: 0 4px 0 10px} .progress {background-color: #82CFFA; height: 10px}
.no_write #file_drop_target, .search #file_drop_target {display: none}
#breadcrumb {padding-top: 1em; font-size: 15px; color: #AAA; clear: both} #folder_actions {width: 50%; float: right} #actions {padding: .5em 0 1em 0; font-size: 15px; color: #AAA}
table {border-collapse: collapse; width: 100%} thead {max-width: 1024px} .sort_hide {display: none}
td {padding: .2em 1em .2em .2em; border-bottom: 1px solid #def; height: 30px; font-size: 12px; white-space: nowrap}
tr:hover {background: #F4FAFF} td.first {font-size: 14px; white-space: normal} td.empty {background: #FFF !important; color: #777; font-style: italic; text-align: center; padding: 3em 0}
tr.broken {background: #FFF4F4} .is_dir .size {color: transparent; font-size: 0}
a.delete {display: inline-block; color: #D00; margin-right: 1em; font-size: 11px; padding: 0 0 0 13px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAADtSURBVHjajFC7DkFREJy9iXg0t+EHRKJDJSqRuIVaJT7AF+jR+xuNRiJyS8WlRaHWeOU+kBy7eyKhs8lkJrOzZ3OWzMAD15gxYhB+yzAm0ndez+eYMYLngdkIf2vpSYbCfsNkOx07n8kgWa1UpptNII5VR/M56Nyt6Qq33bbhQsHy6aR0WSyEyEmiCG6vR2ffB65X4HCwYC2e9CTjJGGok4/7Hcjl+ImLBWv1uCRDu3peV5eGQ2C5/P1zq4X9dGpXP+LYhmYz4HbDMQgUosWTnmQoKKf0htVKBZvtFsx6S9bm48ktaV3EXwd/CzAAVjt+gHT5me0AAAAASUVORK5CYII=) no-repeat scroll 0 2px}
.name {position: relative; padding: 15px 0 10px 40px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABAklEQVRIie2UMW6DMBSG/4cYkJClIhauwMgx8CnSC9EjJKcwd2HGYmAwEoMREtClEJxYakmcoWq/yX623veebZmWZcFKWZbXyTHeOeeXfWDN69/uzPP8x1mVUmiaBlLKsxACAC6cc2OPd7zYK1EUYRgGZFkG3/fPAE5fIjcCAJimCXEcGxKnAiICERkSIcQmeVoQhiHatoWUEkopJEkCAB/r+t0lHyVN023c9z201qiq6s2ZYA9jDIwx1HW9xZ4+Ihta69cK9vwLvsX6ivYf4FGIyJj/rg5uqwccd2Ar7OUdOL/kPyKY5/mhZJ53/2asgiAIHhLYMARd16EoCozj6EzwCYrrX5dC9FQIAAAAAElFTkSuQmCC) no-repeat scroll 0px 12px}
.is_dir .name {padding: 15px 0 10px 40px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAADdgAAA3YBfdWCzAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAI0SURBVFiF7Vctb1RRED1nZu5977VQVBEQBKZ1GCDBEwy+ISgCBsMPwOH4CUXgsKQOAxq5CaKChEBqShNK222327f79n0MgpRQ2qC2twKOGjE352TO3Jl76e44S8iZsgOww+Dhi/V3nePOsQRFv679/qsnV96ehgAeWvBged3vXi+OJewMW/Q+T8YCLr18fPnNqQq4fS0/MWlQdviwVqNpp9Mvs7l8Wn50aRH4zQIAqOruxANZAG4thKmQA8D7j5OFw/iIgLXvo6mR/B36K+LNp71vVd1cTMR8BFmwTesc88/uLQ5FKO4+k4aarbuPnq98mbdo2q70hmU0VREkEeCOtqrbMprmFqM1psoYAsg0U9EBtB0YozUWzWpVZQgBxMm3YPoCiLpxRrPaYrBKRSUL5qn2AgFU0koMVlkMOo6G2SIymQCAGE/AGHRsWbCRKc8VmaBN4wBIwkZkFmxkWZDSFCwyommZSABgCmZBSsuiHahA8kA2iZYzSapAsmgHlgfdVyGLTFg3iZqQhAqZB923GGUgQhYRVElmAUXIGGVgedQ9AJJnAkqyClCEkkfdM1Pt13VHdxDpnof0jgxB+mYqO5PaCSDRIAbgDgdpKjtmwm13irsnq4ATdKeYcNvUZAt0dg5NVwEQFKrJlpn45lwh/LpbWdela4K5QsXEN61tytWr81l5YSY/n4wdQH84qjd2J6vEz+W0BOAGgLlE/AMAPQCv6e4gmWYC/QF3d/7zf8P/An4AWL/T1+B2nyIAAAAASUVORK5CYII=) no-repeat scroll 0px 10px}
.is_synced .name::before {content: ''; position: absolute; top: 8px; left: -2px; width: 16px; height: 16px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB9UlEQVR42o2TTWsTURSGnzuT2KSmKoXUFmObWlKRFkWo3Yi04E7FXyAYcKOIS6vSmlJMcKHoRqHqwi5cuxNB7E6wLiu1RrHaj9RWBBWjSafJzO3NjDEfzkgPDAyHc597zn3fIyiHpkPrHmjcBgL3kOrLZ2FlDizTTjmlkb06F+6NEemOI7RWhND4FyOR0kJaq3yem+DO2VEW3phCFcP1ySSd+4fhPzfX4xbfprg0OCJo6YDbLzP4tuzyOj8Q9hHyCZ6sFCrJ4voyQ4MRQUev6uB5Ed2nl/KxkMaRsL8GcGC7zvlYgMvTOW6+X3OSZtEkcVxhoyXApKUe0W4yHm3gYX/Ic5ob6TxDr3POIyaOiTJA2iqoONHmJ9HTWHNoh18Qa9KZ/lHk5IssiznLG1COnQ2CL4b8Cz3TGeDUqyy/zT8FXoCAEvBBX4ipbwXufjDsXLPq4HtBIqtvcANEghqPDzdxqNnHp18mq2tWTVcT8wb3PxquAPsRh/cFudYbVNZwt2JyNsfVmXwdoFpGKTkdDTDet5VHCwZPq3VXkc6azP4062RsaYdbUxn8FSP1qxHscZbXPeW0jXRxIOJYOfUsSddBbyu7xfxMiitHR5xh27rUMo2P0d4TR9vEMi2l1TKdGyXzzqwUlToJ74bgJtb565L6dxTaABeowVlw/226AAAAAElFTkSuQmCC) no-repeat}
.is_link .name::before {content: ''; position: absolute; top: 8px; left: -2px; width: 16px; height: 16px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAC0ElEQVR42nVTXUiTYRR+Xvfv5nTTac6C5lATsYaky0LLRVeFCF5ETKGsxQRRr0K66yYhkQoSLUME7Sb8vQgiUSkvQtPyYkVkmWyFNN3//75tb9++nJjogY/v5bznec7heZ9DsC8M7TqFokBWKZYLiwmBMpmjgDPqY9acv3xLs49XXXvrSepQf0+vVhak90lk5IpACD6Pz16Sf9eUUsRjABNBLBigUx57uHPq7vvfuwTnzeVi7RnVx6xslKZAh0WSzOPED5vFo3vTs+Lnqo39dWZVPunn8Q8Gq+Va1Je2wh6wYurzEzCxOLY30TZqnuvjEDeGDJPKXNJwWFdTVTdKVJXc+dliF75tL8NhT0wPt8w3cASmEcO6XEE02FEspUxZbjUuFTfjiKyQEyUUDaB7xoQg7PC66MZg85yGlF8+Ts4aC8MyORGK+Okw63ugkh6FK/QHSokas1+m8dryEpniHPgiDhCZCzwegd9LmeUJq4gl0AjONWki0gxCTuRU4Zb+PtfdG3Kj+1UnvNQGsWTPs+2IHPBR+mHcJiInWYJqoybCTkAII0V77SPkydVw+reQJVVgYWMS736OIUOohD/qQpDxcQTsBJSbYEeDMKuBiCYovG42EecBaQmcUteioaIZeZlq8NOECDF+9C6Y4AlvJzWIrkxbxRzB9SHD9+xcot2vfoyhCPoIOgwPUFZQweWevu/CmjP5CnR9uGVOyxE0DdSN5eSTxqQ4B4UCxbh6ug2bbivGLQ9BBDHWB3Ri1DzfyCGu9V24KZGmPWediIOcGI9RVjSAz9pbIgPcDiASordftM4PctV6Y4mgqEa9wBcQvUQKCEXAQbsQjQBBP0e4ZFvdqnk7YInutrvYocvML1X0JJ1NKUlPYlPDsHjuI4QG2d+Ifc19Z6b3k/e/bUxFlbFEpDgm00mzREU8IS87mUswcUfQHWXX2b+6OPI1srf+LyqQH9iE2fJzAAAAAElFTkSuQmCC) no-repeat}
.path, .path:visited {font-size: 12px; color: #808080; margin-left: 1em}
.download {padding: 4px 0 4px 18px; margin-right: 1em;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2klEQVR4nJ2ST2sTQRiHn5mdmj92t9XmUJIWJGq9NHrRgxQiCtqbl97FqxgaL34CP0FD8Qv07EHEU0Ew6EXEk6ci8Q9JtcXEkHR3k+zujIdUqMkmiANzmJdnHn7vzCuIWbe291tSkvhz1pr+q1L2bBwrRgvFrcZKKinfP9zI2EoKmm7Azstf3V7fXK2Wc3ujvIqzAhglwRJoS2ImQZMEBjgyoDS4hv8QGHA1WICvp9yelsA7ITBTIkwWhGBZ0Iv+MUF+c/cB8PTHt08snb+AGAACZDj8qIN6bSe/uWsBb2qV24/GBLn8yl0plY9AJ9NKeL5ICyEIQkkiZenF5XwBDAZzWItLIIR6LGfk26VVxzltJ2gFw2a0FmQLZ+bcbo/DPbcd+PrDyRb+GqRipbGlZtX92UvzjmUpEGC0JgpC3M9dL+qGz16XsvcmCgCK2/vPtTNzJ1x2kkZIRBSivh8Z2Q4+VkvZy6O8HHvWyGyITvA1qndNpxfguQNkc2CIzM0xNk5QLedCEZm1VKsf2XrAXMNrA2vVcq4ZJ4DhvCSAeSALXASuLBTW129U6oPrT969AK4Bq0AeWARs4BRgieMUEkgDmeO9ANipzDnH//nFB0KgAxwATaAFeID5DQNatLGdaXOWAAAAAElFTkSuQmCC) no-repeat scroll 0px 4px}
.link {padding: 4px 0 4px 20px; margin-right: 1em;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAADWElEQVR4XnWOa0ybVRzGn/dSStGxDWEuWwiG4aW42BmmVo3JmGQmxjkuW5YwzRYb21IY0GyFAU0BSZiLRD/tg5m3GOO8ZAqbH5ahcQb3gXDxMiISthAmpVg6aLsCbd/L49stJpuJv+T3P+fkyf/JEYpODiKDTkDTxTJFld9WdbGCFCAK4m0lUf/eJCknRFEdEwQddyPeWSYUlacl0+pow76eisGOXvzQ9SY+aXbipMuO/eXeihzz0qiqZZ0mxXsLSEDV9NNytsXz3sHncXyHE3riDCan/8C1G1dxbe4irA8N47WXHcixxDz/LRF16mWSbPL0VNpRumEj5tJhRFJLWEEU27bsxrZNPbg89TGyTTHUV74CSdY8OqUyQLhToClK3+MlxXh2s4yoGsFyWse63EYUPmhHXJtGihNIKoV4f0hFdC0XL+30QVOkd8h/CwRxl3VrAYIJYD6Rj2DsBazos4ipQQTjVmM5D6q2DlnyLZwdG4K1aAS6YConBOiGYrbZgluajPlVHcFVIMpxJDCDpDEL1g+iIHcGueYJUEhiObkFyynJKABSkJCEDFlVgQc2foSrN11Iwbhn3cR9ZkASAEEBfp09gsnFWiQZxSqBT3/7AGuCjl5ehqIRsmaMrXn9uBJ+BiXjv0NdXMN4qhdKmri/aBw/F/cipSWwJ/QdSlZmoAkyIM4iTmmMglCGzf6B4R2f/UJf34e8eOECdVXnfDDMub/CPPfVedZ37uPxPi8vGVmGeCzOUGiB577p54l2/wTyDrRUFZy6wl5/GzMEAp10OBxsb+tge0eA/o5O+v0ZA+wwdDpdrDlwkH9OTdMf6CIMcjb4zn4RaDnGyN9hY8HPne9eotvtZoZwOMLZG3P88aeh29kuh+9MVVU1v+0/z0BnN7Hp1BAMClu9TcbXQ+zqfot1dR7WVNewu7uHra1tbGlpZWNjM2trD9FlZNXV+/n5l1/zaJOXQru3CRqAREq9Xr77xeLHrFZEFsMYGRnFwMAAlmiGyZKzVLI+K690+3bYbDak02mEFhYwMjyso6HhKOoNDUoPvX74uruuns3HfHS66viE7clwfn7+HgA2u/256aeettPl9vDwkTe499XKyMOPPLpXwL2UGlrueiuGk5nzf7KpfwAt7sFCq0puUgAAAABJRU5ErkJggg==) no-repeat scroll 0px 4px}
.rename {padding: 4px 0 4px 20px; margin-left: 1em; visibility: hidden; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAZ9JREFUeNqkUzlLA0EU/mZ2ks1hQAQtRDyCFlYpFDvBSkjjj1DwiqCVB9Y2VhYKYm1jIQjmB2jphX8hhY3gUQjZze7OPF92syroisGBZR773ne8mTeCiPCfJZIS6yvzZIQFwyUSBEkau/tHoh3ysea3UZmjOP6pSA1vn5HrawTmsxViVRKsa6XgP5+ge7N6K7QPQU0/UZ3kuK84COUw+HqrjOZOXzuSAlYqg53KMa44H3guyJgPiYwEFi+eoHxt0NuZxctDDRaDhGANFjG8w9ioM3GH8wTXdWBiAi7oLxbhBo9Q8S1MV9+QVRKSSQz/c7XAzWwPNLeWKxQglGoRsM8WxnBOxY5tC0wAdgEGRSRQdgjK57JQyoLWOu7u8xDjMaj7JmSUIgI7Ue2HbTud/n4FTY04vl8utT9E7ERa+H0SbbaetFLcixoYGUL5tIaGF4RUIZ1UIJWGSGcxms9g6vwV5DkQgcc9BTyZEbjuNaBuVicnyG+YJJXS0sLt5UzXeNtvYa2ySEaqVgkfLivvHRyKPxMkzP7dN4L/Pud3AQYAKoqz1m0k8iEAAAAASUVORK5CYII=) no-repeat scroll 0px 4px}
.choose {padding: 4px 0 4px 20px; margin-left: 1em; visibility: hidden; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAM1BMVEX/3Kb/xnDb29vdkSD/pBv/uU+puazErYCtdyb/sDrdkySpsKz/83GTq7v///8AAAD///8uDwBVAAAAEXRSTlP/////////////////////ACWtmWIAAAABYktHRA5vvTBPAAAAImhJU1QABQAEAAQAAwACAAIAAQABAAEAAQABAAEACAAUAAkAEgCv5/567wAAABt0RVh0U29mdHdhcmUAZ2lmMnBuZyAwLjYgKGJldGEpqt1pkgAAAFxJREFUeJxdzksOwCAIBFCo2q+D3P+0tbECLZtJXoAM6W9I64gAtWrlCDmntdhOz3SKbBxP0iJyGRCXY19ag58oMZoJDXOZz02s0RSv+IpDFxFEUPQ+iPDIFxTADWX7DjtAK6wLAAAAAElFTkSuQmCC) no-repeat scroll 0 3px}
#paste {padding: 4px 0 4px 20px; margin-right: 1em; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAJRSURBVBgZBcExiJZlHADw3/O+732enKYdQVeklWBeoSBFtmgNNrRcQ9DSFBQZDU4OEYSNbQUtCg5FEAUpDdXSUliBQRBEBBXeVuFZnvKd1/e9z/P/9/uVzATnX37wEfwCAICbpy6s7wUAACjnXnrgUbyFtV3Ld3vhjbO2rv8Alu465sOzr9veugUf4dKpC+sXAWDApWdeObNv+Z57/fPV+zJTm22BzHTiyD5LR0/KzLXPzr/3LC4CwID7l1fus/n7FTHetv7JO2QiXc8fpbTx83eWV4/tBgCAAbLORR11+w+LVmWmj9tpLUMEcPO3LeX401599/O8MVv59c/1vx67fG5te4Boo6ijGGfa7D+kNoQ3n1u1MQ0FkWlsYeiP+ODK5sN96a8++doXBweIOhOtkqEUMum7zo3b6Y+N1HVprOHWdvXUQzsdP7TX0qRb+TbbTx1EnYs618a5qE3UBvrC4sCkLyZ9sTjpXNvcduhOXnxijzrmgQFinMlxLmuIsZGpLaZSWOjJJPticehc/TdN/555fP8OC0NngKhzUZsYm6hBpMhUFH3XASVFJDt6pSv6vpcYIMcm503UJmojgABFEfrCZOiUTBFFKUUmA9SxamMTrYmxkURLBUNHVzqR9IUuMGHnQGYaIOdVjE22JmvISNCiYgAAAJGVKAZc3p5OT+zatyprE7WRicGsTrEXAADM6lSJrgx4++svP92NowBw7fDzFroD9iyOMulKUQpQ0Hd3iKzzkpkAAODkme+/6btykG6F3KIgQVFKZJvuWVrY+T+vNUkTODP9hQAAAABJRU5ErkJggg==) no-repeat scroll 0 4px}
#newdir {padding: 4px 0 4px 20px; margin-right: 1em; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACRUlEQVR42p2STUhUURTH/+e9NzNmxjiYkkyWaVELCUNyigSVjMIPWkRSu1oEUVS4aRFTlEFQVARKhoT0gZmLhLICh4lBUscKJfsWAnV0lLRxPhxm3sx7973uSEaYC6f/3ZzLPed37v+eS1iO7NhsXme+bFtvK2UaY+5RtyMyHrHjCiYocb7v6CWSJElMxLqusxd37fqf4pMosJZYe07vOGHOE3Oh6gq+KyO41dc45evx2eYBzS5fZ6oJ1YmYafCNTQYr3V1tg0HZS32bml7uqSmpKLJkoJxqEWaz6Ccn+ma86O1493Ae0OCYdq0womyhqa5xEL9DTImgLpCPmlW7UZm9E8WrKxBV5/Ah8Abtkw64xt3TdK5t9KwoCcdFARsWW49G/biaWoiDxirUrC1DUVYpZCWMT/4BtHo64Qz1R+lwo8djkCiLCKbFAKbE8DytCmrmMLZZ+HNYrsOvTOF+6AaGAsDKieIIHWv5+YV3z+P5/wC4GQz72tG98QxSZYb9GdWY4xacwW7EjCa9/NudEap7HH5L0Lfy5CUAgBqX8fFHCwatTQgaPSC+LHI+tk/VxbdkHxqi80+jr3Rd28XHtyQgIY2pCM6MITjLASQgPSMX5sycmCAaeumaQ36mMm0vBxiX9al+i4jikih00e3X8UdxhR3QkgQIAsWNkviEHgyozXJMPcIBhqQAREqKSbpHHZ/ZzbDMTnELUpIW1LQUsYHqW90X03MKLiRTvKCQ92s9Bwlr+BQK+V5Msp4Jgvie/qfz3/oFDZnzKHtdCtMAAAAASUVORK5CYII=) no-repeat scroll 0 4px}
#newfile {padding: 4px 0 4px 20px; margin-right: 1em; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACS0lEQVR42o3TSWgTYRQA4DfZTEKWJghiFc12cbIYEtEogkuIilBQehJ6Eix68aTgctGLerAnD1ZqMCBePShGMCmUigZ6iJnEEjpZWyFhhoZMQtNmmcz4T8BhEo364M0wzPwf///ePAxQxOPxMyqVyiyTyUAaGIb10W0oeZ7vdzqdSjAYXBt8I1zS6XTC4XAE4D8jm80+9fv9t0UglUolLBZLgGEYaLfbYxfq9XowmUxQLpcf4Th+XwQIgkjY7fZAo9GAXq83FtBoNAOkVCo9cDqdD0Ugk8kMgHq9Dt1udyyg1WoHQLFYvOdyuR7/BtA0/dcj6HQ6MJvNUCgUbrnd7jkp8BUBxwUAVVhcYDAYhgDUqcEx8vn8TY/H80wEksnkZ6vVehK1DVCbxu5ALpeDQqEAkiSve73eF9IdLNlstlNCF0ZrIIBkbQV2gAajehKOWs8jIHfV5/O9kgKL6Ahn/1SDZO0t4DYcTJpJyNWWoFLbhANsaOb0idAbKfAJAaFWqwUsy4qL15ks9LVl2GfA4eDEMfjyYx6+U++B2dh77c50+KUU+IiAC6NAmoqBcTcLh/dMg1phgDbbhIXkFKxXG3fnLhFPpEX8gP7Ei81mc6gL9PYG5PnXUGuvwo0jMQh/uwzMToWvVtXnnl/JxEUAzcI7NAtTo8UTMpZbAKI+j6rPQb+P8cRyL7y6WJ9dW2Z4EYhGo4eUSqUWTaM4daigXCQSUVEUtWsLNvfLjS0bU+2RFLm1gt63UG6j5DD4RyAU4zhOOuecsMFfDz8BCVseICDGNc8AAAAASUVORK5CYII=) no-repeat scroll 0 4px}
#paste {opacity: 0.5; text-decoration: none; cursor: default} .chosen #paste {opacity: 1; text-decoration: underline; cursor: pointer} .no_write #paste, .search #paste {display: none}
.no_write #newdir, .search #newdir, .no_write #newfile, .search #newfile {display: none}
#refresh {padding: 4px 0 4px 16px; margin-left: 1em; font-size: 12px;
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAADFklEQVR42mNkwAKmZjrpyQgLB/DyiagwcfN//vzz19lP375tjq6Z8RpdLSOMURdlpiQuyPdPmJ97sp6SojcfjwAjFwc/AyuPAAMjFz/Dmy+ff12+fmnBi9cvq1JblrxFMaAl0VHE0UDzMisrCzsvL7fg/79/GP79/vX/z99//7i5+Zk4+UUY/7NxMfxj52I4ferA+ZDyOUYoBswqjzCJ9As5/eXTa4aH96+9v3bndvOr95/Xvvn045kAD6eAiACPnaSEeCEzK5vo+ee/A2t7F1xHMWBxS2ZIRGTq6i/P7zDcvnzsw9YjR90bl54+hezX4hAjxm+8SlxSFqGlXAJiWg+fPE+ZVBz1iTGhxktGg1ecT+w/m8n/jx/evnvz6vXHz5/ut6w4ixFgwaUTeN09XB+oKMkKHT13/fbJI8fCGJcc7vn84cO72/fv3q3pLVi5jQEP8CmeXObp79PJzMzEcPfeo9fnjx3OZDx8Z+0/ZpZ/jIdOH+yuCJ1Shs8A6/j6BB5BYQNLR4f8R3fvvXl485Is476rK74ICHNxHzl9eGWeb3cEAwHgWTS1yMDSsvfl8+dfHt24ws+4/tis42oashZX7l54e+H8Vdn2tCXf8RkQ2b56u7KWpseTB/cfLMj3VWSctaWxys7WvPXtlxcMu/cfqGmIWdCKS7NX4QRbIweXA7wCfEw3Ll1aOT/XJ4KxdlaKqK2d0Q0uXg6hF29e/jl+7HzCj2+/jvLwcxZ1pizPg2n2zu/VUDM03qumqS7Fwsryf9+WLc7L6xL3g9NBx+o0Nw1N5Q1sbBycv379+f/kybO7+hpGSieOn/Uojezb7Vc4MVvTwKBNVU2RT1iQl+HEkRNTO1M8c1DyQumsMFMZWcn5qkoq2gJcwgxivPIMr16+fbxq4zG9L391N1tamdoI8HEznDtzfuaXL1+zJhaG/0MxAAQyenyZubk4Q10cHBaI88kzPnrwcv2h49crXn9SLlNRVvJ4/OhB1Zy6tBVYcyM8tRXZCqpry+cy/GKd3ZY5/zlIzCIoR5Cdg+PTwWU9f9HVAwD9xESPgmOhJQAAAABJRU5ErkJggg==) no-repeat scroll 0 3px}
tr:hover .rename, tr:hover .choose, tr:hover .paste {visibility: visible}
<?php if ($serverinfo) { ?>
#phpinfo {position: absolute; top: 10%; left: 10%; right: 10%; bottom: 10%;	display: none; box-shadow: 1px 1px 4px rgba(0, 0, 0, 0.5)}
#phpinfo.shown {display: block} #phpinfo a {position: absolute; top: -12px; right: -12px}
#phpinfo iframe {width: 100%; height: 100%; border: 1px solid #82CFFA}
#phpinfoclose {position: absolute; top: 0; right: 0; width: 1em; height: 1em; background: #FFF; border: 2px #82CFFA solid; border-radius: 1em; color: #82CFFA; font-size: 1.5em; font-weight: normal; text-align: center; text-decoration: none !important}
<?php } ?>
#breadcrumb div {display: inline} #breadcrumb span {margin: 0 .25em 0 .25em}
#searchlbl {display: none; font-size: 15px} .search #searchlbl {display: inline}
#table input, #searchfield {width: 12em; border: 1px #C0C0C0 solid; border-radius: 4px; color: #808080; padding: .25em; outline: none} #table input:focus, #searchfield:focus {border-color: #82CFFA; color: #000}
#searchbtn {background: none; border: 1px #C0C0C0 solid; border-radius: 4px; color: #808080; padding: .25em; outline: none} #searchbtn:hover {background: #F0F8FF; border-color: #82CFFA; color: #000}
span.hit {background: #FFFF80}
#table td input {width: 50%; display: none} #table td.renaming input {display: inline} #table td.renaming a.name {display: none}
#operations {position: absolute; top: 0; left: 0; width: 100%; height: 0; text-align: center}
#totalop {background: #82CFFA; padding: 1em; border-bottom-left-radius: .5em; border-bottom-right-radius: .5em; color: white; position: relative; top: 1em}
#totalop.error {background: red} #totalop.hidden {display: none}
</style>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>
(function($) {
	$.fn.tablesorter = function() {
		var $table = this;
		this.find('th').click(function() {
			var idx = $(this).index();
			var direction = $(this).hasClass('sort_asc');
			$table.tablesortby(idx, direction);
		});
		return this;
	};
	$.fn.tablesortby = function(idx, direction) {
		var $rows = this.find('tbody tr');
		function elementToVal(a) {
			var $a_elem = $(a).find('td:nth-child(' + (idx + 1) + ')');
			var a_val = $a_elem.attr('data-sort') || $a_elem.text();
			return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
		}
		$rows.sort(function(a, b) {
			var a_val = elementToVal(a), b_val = elementToVal(b);
			var a_isdir = $(a).hasClass('is_dir');
			var b_isdir = $(b).hasClass('is_dir');
			if (a_isdir != b_isdir) {return a_isdir ? 0 : 1;}
			return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
		});
		this.find('th').removeClass('sort_asc sort_desc');
		$(this).find('thead th:nth-child(' + (idx + 1) + ')').addClass(direction ? 'sort_desc' : 'sort_asc');
		for (var i = 0; i < $rows.length; i++) this.append($rows[i]);
		this.settablesortmarkers();
		return this;
	}
	$.fn.retablesort = function() {
		var $e = this.find('thead th.sort_asc, thead th.sort_desc');
		this.tablesortby($e.length ? $e.index() : 0, $e.length ? $e.hasClass('sort_desc') : true);
		return this;
	}
	$.fn.settablesortmarkers = function() {
		this.find('thead th span.indicator').remove();
		this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
		this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
		return this;
	}
	$.fn.addop = function() {
		this.operations++;
		$("#totalop").removeClass('error');
		$("#totalop").text("Outstanding operations: " + this.operations);
		if (this.optimeout) clearTimeout(this.optimeout);
		if (this.operations == 1) this.optimeout = setTimeout(function(){$("#totalop").removeClass('hidden');}, 5000);
		return this;
	}
	$.fn.removeop = function(error) {
		this.operations--;
		if (error) {$("#totalop").addClass('error');$("#totalop").removeClass('hidden');}
		$("#totalop").text("Outstanding operations: " + this.operations);
		if (this.operations == 0) {
			if (error) this.optimeout = setTimeout(function(){$("#totalop").addClass('hidden');}, 5000);
			else $("#totalop").addClass('hidden');
		}
		if (this.optimeout) clearTimeout(this.optimeout);
		return this;
	}
})(jQuery);
$(function() {
	var _XSRF_ = <?php echo "'".$cookie_xsrf."'" ?>;
	var XSRF = (document.cookie.match('(^|; )' + _XSRF_ + '=([^;]*)') || 0)[2];
	var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
	var WEB_ROOT = <?php echo '\''.$root_web.'\'' ?>;
	var chosen = null; var chosen_can_move = false;
	var $opers = $('#operations'); $opers.operations = 0; $opers.optimeout;
	var $tbody = $('#list');

	$(window).bind('hashchange', list).trigger('hashchange');
	$('#table').tablesorter();

	$('#newdir').live('click', function(data) {
		var folder = $("#paste").attr('data-file');
		var name = prompt ("New folder name:", "New folder");
		if (!name) return false;
		name = name.substr(name.lastIndexOf('/') + 1);
		if (!name) return false;
		$opers.addop();
		$.post("", {'do': 'mkdir', file: folder, name: name, xsrf: XSRF}, function(response) {
			$opers.removeop(response && response.error);
			list();
		}, 'json');
		return false;
	});

	$('#newfile').live('click', function(data) {
		var folder = $("#paste").attr('data-file');
		var name = prompt ("New file name:", "New file");
		if (!name) return false;
		name = name.substr(name.lastIndexOf('/') + 1);
		if (!name) return false;
		$opers.addop();
		$.post("", {'do': 'new', file: folder, name: name, xsrf: XSRF}, function(response) {
			$opers.removeop(response && response.error);
			list();
		}, 'json');
		return false;
	});

	$('.delete').live('click', function(data) {
		if (confirm ('This cannot be undone. Are you sure?')) {
			$opers.addop();
			$.post("", {'do': 'delete', file: $(this).parent().parent().attr('data-file'), xsrf: XSRF}, function(response) {
				$opers.removeop(response && response.error);
				list();
			}, 'json');
		}
		return false;
	});

	$('.rename').live('click', function(data) {
		function createSelection(field, start, end) {
			if (field.createTextRange) {
				var selRange = field.createTextRange();
				selRange.collapse(true);
				selRange.moveStart('character', start);
				selRange.moveEnd('character', end);
				selRange.select();
				field.focus();
			} else if (field.setSelectionRange) {
				field.focus();
				field.setSelectionRange(start, end);
			} else if (typeof field.selectionStart != 'undefined') {
				field.selectionStart = start;
				field.selectionEnd = end;
				field.focus();
			}
		}
		var $this = $(this);
		var file = $this.parent().parent().attr('data-file');
		var $editbox = $this.parent().find('input');
		if (!$editbox.length)
		{
			$editbox = $('<input type="text"/>');
			$editbox.keyup(function(e) {
				if (e.keyCode == 13) {
					$(this).parent().removeClass('renaming');
					var file = $(this).parent().parent().attr('data-file');
					var name = $(this).attr('value');
					if (!name) return false;
					name = name.substr(name.lastIndexOf('/') + 1);
					if (!name) return false;
					name = file.substr(0, file.lastIndexOf('/') + 1) + name;
					$opers.addop();
					$.post("", {'do': 'rename', file: file, name: name, xsrf: XSRF}, function(response) {
						$opers.removeop(response && response.error);
						list();
					}, 'json');
				}
				else if (e.keyCode == 27) $(this).parent().removeClass('renaming');
				return false;
			});
			$editbox.blur(function(e) {
				$(this).parent().removeClass('renaming');
				return false;
			});
			$this.parent().children(":first").before($editbox);
		}
		var val = file.substr(file.lastIndexOf('/') + 1);
		var p = val.lastIndexOf('.');
		$editbox.attr('value', val);
		$this.parent().addClass('renaming');
		createSelection($editbox[0], 0, p ? p : val.length);
		return false;
	});

	$('.link').live('click', function(data) {
		function makeid(len)
		{
			var text = "";
			var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			for (var i = 0; i < len; i++) text += possible.charAt(Math.floor(Math.random() * possible.length));
			return text;
		}
		var file = $(this).parent().parent().attr('data-file');
		var ext = file;
		var idx = ext.lastIndexOf('.');
		ext = (idx == -1) ? "" : ext.substr (idx + 1);
		var link = prompt ("Public link name:", makeid(6) + (ext ? '.' + ext : ''));
		if (!link) return false;
		$opers.addop();
		$.post("", {'do': 'link', file: file, name: link, xsrf: XSRF}, function(response) {
			$opers.removeop(response && response.error);
			if (response && response.error) return;
			var location = window.location.toString();
			if (prompt ("The public link has been created. Display it in its folder?",
			  location.substr(0, location.lastIndexOf('/') + 1)
			  + <?php echo "'".$public."'" ?> + '/' + link)) {
					window.location.hash = <?php echo "'".$public."'" ?> + link.substr(0, link.lastIndexOf('/'));
			}
		}, 'json');
		return false;
	});

	$('.choose').live('click', function(data) {
		chosen = $(this).parent().parent().attr('data-file');
		chosen_can_move = $(this).attr('can-move') == 'yes';
		if (!($('body').hasClass('chosen'))) $('body').addClass('chosen');
		return false;
	});

	$('#paste').live('click', function(data) {
		if ($('body').hasClass('no_write')) return false;
		if (!$('body').hasClass('chosen')) return false;
		$('body').removeClass('chosen');
		var oldname = chosen.substr(chosen.lastIndexOf('/')+1);
		var folder = $(this).attr('data-file');
		folder = folder.substr(0, folder.lastIndexOf('/') + 1) || folder + '/';
		var newname = folder + oldname;
		$opers.addop();
		$.post("", {'do': chosen_can_move ? (confirm ("Copy or move?") ? 'copy' : 'move') : 'copy', file: chosen, name: newname, xsrf: XSRF}, function(response) {
			$opers.removeop(response && response.error);
			list();
		}, 'json');
		chosen = null;
		return false;
	});

	$('#refresh').live('click', function(data) {
		list();
	});

	$('#search').submit(function(e) {
		var hashval = window.location.hash.substr(1),
		  $name = $(this).find('[name=name]');
		var query = $name.val();
		e.preventDefault();
		if ($name.val().length) {
			$opers.addop();
			$.get('?', {'do': 'search', name: $name.val(), xsrf: XSRF, file: hashval}, function(data) {
				$opers.removeop(!data.success);
				$('body').addClass('search');
				$('#searchtext').text(query);
				$tbody.empty();
				if (data.success) {
					$.each(data.results, function(k, v) {
						$tbody.append(renderFileRow(v, true, query));
					});
					!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>Nothing has been found</td</td>')
					$('body').addClass('no_write');
				} else {
					console.warn(data.error.msg);
				}
			}, 'json');
		}
		$name.val('');
		return false;
	});

	$('#remote').live('click', function(data) {
		var folder = $("#paste").attr('data-file');
		var url = prompt ("Remote URL:", "");
		if (!url) return false;
		$opers.addop();
		$.post("", {'do': 'fetch', file: folder, url: url, xsrf: XSRF}, function(response) {
			$opers.removeop(response && response.error);
			list();
		}, 'json');
		return false;
	});

	$('#showphpinfo').bind('click', function() {
		$phpinfo = $('#phpinfo');
		$iframe = $phpinfo.find('iframe');
		if (!$iframe.attr("src"))
		{
			$btn = $phpinfo.find('a');
			$btn.bind('click', function() {
				$phpinfo.removeClass('shown');
			});
		}
		$iframe.attr('src', '?do=phpinfo');
		$phpinfo.addClass('shown');
		return false;
	});

	$('#file_drop_target').bind('dragover', function() {
		$(this).addClass('drag_over');
		return false;
	}).bind('dragend', function() {
		$(this).removeClass('drag_over');
		return false;
	}).bind('drop', function(e) {
		e.preventDefault();
		var files = e.originalEvent.dataTransfer.files;
		$.each(files, function(k, file) {
			uploadFile(file);
		});
		$(this).removeClass('drag_over');
	});
	$('input[type=file]').change(function(e) {
		e.preventDefault();
		$.each(this.files, function(k, file) {
			uploadFile(file);
		});
	});

	function uploadFile(file) {
		var folder = window.location.hash.substr(1);

		if (file.size > MAX_UPLOAD_SIZE) {
			var $error_row = renderFileSizeErrorRow(file, folder);
			$('#upload_progress').append($error_row);
			window.setTimeout(function() {$error_row.fadeOut();}, 5000);
			return false;
		}

		var $row = renderFileUploadRow(file, folder);
		$('#upload_progress').append($row);

		var fd = new FormData();
		fd.append('file_data', file);
		fd.append('file', folder);
		fd.append('xsrf', XSRF);
		fd.append('do', 'upload');

		var xhr = new XMLHttpRequest();
		xhr.open('POST', '?');
		xhr.onload = function() {
			$row.remove();
			list();
		};
		xhr.upload.onprogress = function(e) {
			if (e.lengthComputable) {
				$row.find('.progress').css('width', (e.loaded / e.total * 100 | 0) + '%');
			}
		};
		xhr.send(fd);
	}
	function renderFileUploadRow(file, folder) {
		return $row = $('<div/>')
		.append($('<span class="fileuploadname"/>').text((folder ? folder + '/' : '') + file.name))
		.append($('<div class="progress_track"><div class="progress"></div></div>'))
		.append($('<span class="size"/>').text(formatFileSize(file.size)))
	};
	function renderFileSizeErrorRow(file, folder) {
		return $row = $('<div class="error"/>')
		.append($('<span class="fileuploadname"/>').text('Error: ' + (folder ? folder + '/' : '') + file.name))
		.append($('<span/>').html(' file size: <b>' + formatFileSize(file.size) + '</b>'
		+ ' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>'));
	}

	function list() {
		$('body').removeClass('search');
		var hashval = window.location.hash.substr(1);
		$('#paste').attr('data-file', hashval);
		$opers.addop();
		$.get('?', {'do': 'list', 'file': hashval}, function(data) {
			$opers.removeop(!data.success);
			$tbody.empty();
			var $crums = $('#breadcrumb');
			$('#breadcrumb div').remove();
			$crums.prepend(renderBreadcrumbs(hashval));
			if (data.success) {
				$.each(data.results, function(k, v) {
					$tbody.append(renderFileRow(v, (v.path == 'public') || (v.path.indexOf("public/") == 0)));
				});
				!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td</td>');
				data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
			} else {
				console.warn(data.error.msg);
			}
			$('#table').retablesort();
		}, 'json');
	}
	function renderFileRow(data, shareDisable, fromSearch) {
		var $link = $('<a class="name"/>')
		.attr('href', data.is_dir ? '#' + data.path : WEB_ROOT + data.path)
		.attr('target', data.is_dir ? "_self" : "_blank")
		.html(fromSearch ? data.name.replace(fromSearch, '<span class="hit">' + fromSearch + '</span>') : data.name);
		var $plink = $('<a class="path"/>');
		if (fromSearch) {
			var path = data.path.lastIndexOf('/');
			path = data.path.substr(0, (path == -1) ? 0 : path);
			$plink.attr('href', '#' + path)
			.text('/' + path);
		}
		else if (data.is_link && data.link_target) {
			var path = data.link_target.lastIndexOf('/');
			path = data.path.substr(0, (path == -1) ? 0 : path);
			$plink.attr('href', '#' + path)
			.text('/' + data.link_target);
		}
		var $rename = $('<a href="javascript:void(0)" class="rename"/>')
		.text("Rename");
		var $choose = $('<a href="javascript:void(0)"/>')
		.addClass('choose')
		.attr('can-move', data.is_writable ? 'yes' : 'no')
		.text("Choose");
		var $dl_link = $('<a/>').attr('href', '?do=download&file=' + encodeURIComponent(data.path))
		.addClass('download').text('Download');
		var $delete_link = $('<a href="#"/>').addClass('delete').text('Delete');
		var canShare = <?php echo $public ? 'true' : 'false' ?>;
		var $llink = (!canShare || shareDisable || data.is_link) ? '' : $('<a href="#"/>').addClass('link').text("Share");
		var perms = [];
		if (data.is_readable) perms.push('r');
		if (data.is_writable) perms.push('w');
		if (data.is_executable) perms.push('x');
		var canCopyFolder = <?php echo $max_copy_depth ? 'true' : 'false' ?>;
		var canZipFolder = <?php echo $max_zip_depth ? 'true' : 'false' ?>;
		var $html = $('<tr/>').attr('data-file', data.path)
		.addClass(data.is_dir ? 'is_dir' : '')
		.addClass(data.is_link ? 'is_link' : '')
		.addClass(data.link_broken ? 'broken' : '')
		.addClass(data.is_synced ? 'is_synced' : '')
		.append($('<td class="first"/>').append($link).append(fromSearch || data.is_link ? $plink : '')
		  .append((data.is_deleteable && !fromSearch) ? $rename : '').append((data.is_readable && !data.is_link) ? (data.is_dir ? (canCopyFolder ? $choose : '') : $choose) : ''))
		.append($('<td/>').attr('data-sort', data.is_dir ? -1 : data.size)
		  .html($('<span class="size"/>').text(formatFileSize(data.size))))
		.append($('<td/>').attr('data-sort', data.mtime).text(formatTimestamp(data.mtime)))
		.append($('<td/>').text(perms.join('')))
		.append($('<td/>').append($llink).append(data.is_dir ? (canZipFolder ? $dl_link : '') : $dl_link)
		  .append(data.is_deleteable ? $delete_link : ''))
		return $html;
	}
	function renderBreadcrumbs(path) {
		var base = "", $html = $('<div/>').append($('<a href=#>Home</a></div>'));
		$.each(path.split('/'), function(k, v) {
			if (v) {
				$html.append($('<span/>').text('▸'))
				.append($('<a/>').attr('href', '#' + base + v).text(v));
				base += v + '/';
			}
		});
		return $html;
	}
	function formatTimestamp(unix_timestamp) {
		var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
		var d = new Date(unix_timestamp * 1000);
		return [m[d.getMonth()], ' ', d.getDate(), ', ', d.getFullYear(), ' ',
			(d.getHours() % 12 || 12), ':', (d.getMinutes() < 10 ? '0' : '') + d.getMinutes(),
			' ', d.getHours() >= 12 ? 'PM' : 'AM'].join('');
	}
	function formatFileSize(bytes) {
		var s = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
		for (var pos = 0; bytes >= 1000; pos++, bytes /= 1024);
		var d = Math.round(bytes * 10);
		return pos ? [parseInt(d / 10), '.', d % 10, ' ', s[pos]].join('') : bytes + ' bytes';
	}
});
</script>
</head><body class="no_write">
<header id="top">
	<div><div id="logout">Welcome, <?php echo $login ?>. (<a href="?do=logout">Logout</a>)</div>
	<form action="?" method="post" id="search"/>
		<input id="searchfield" type="text" name="name" value=""/>
		<input id="searchbtn" type="submit" value="Search"/>
	</form>
	<div id="file_drop_target">Drag Files Here To upload<?php echo ($curl_enable ? ', fetch <a id="remote" href="javascript:void(0)">remotely</a>' : '') ?>, <b>or</b>&nbsp;<input type="file" multiple/></div>
	</div>
	<div id="breadcrumb">
		<label id="searchlbl" href="javascript:void(0)"><span>▸</span>Search:&nbsp;<b id="searchtext"></b></label>
		<a id="refresh" href="javascript:void(0)" title="Refresh"></a>
	</div>
	<div id="actions">
		<a id="newfile" href="javascript:void(0)">New file</a>
		<a id="newdir" href="javascript:void(0)">New folder</a>
		<a id="paste" href="javascript:void(0)">Paste</a>
	</div>
	<div id="operations"><span id="totalop" class="hidden"></span></div>
</div>
<div id="upload_progress"></div>
<table id="table"><thead><tr>
	<th class="col-name">Name</th>
	<th class="col-size">Size</th>
	<th class="col-lastmod">Modified</th>
	<th class="col-permissions">Permissions</th>
	<th class="col-actions">Actions</th>
</tr></thead><tbody id="list">
</tbody></table>
<footer><b>SFM</b>: simple &amp; secure personal file manager.<?php if ($serverinfo) { ?> (<a id="showphpinfo" href="javascript:void(0)">PHP info</a>.)<?php } ?><footer>
<?php if ($serverinfo) { ?><div id="phpinfo"><a id="phpinfoclose" href="javascript:void(0)">&times;</a><iframe></iframe></div><?php } ?>
</body></html>
