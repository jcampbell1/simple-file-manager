<?php
/********************************
 * Simple PHP File Manager
 * Copyright John Campbell (jcampbell1)
 *
 * Liscense: MIT
 ********************************/

/* Uncomment section below, if you want a trivial password protection */

/*
$PASSWORD = 'sfm'; 
session_start();
if(!$_SESSION['_sfm_allowed']) {
	// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
	$t = bin2hex(openssl_random_pseudo_bytes(10));	
	if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
		$_SESSION['_sfm_allowed'] = true;
		header('Location: ?');
	}
	echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p /></form></body></html>'; 
	exit;
}
*/

// must be in UTF-8 or `basename` doesn't work
setlocale(LC_ALL, 'en_US.UTF-8');

$tmp = realpath($_REQUEST['file']);
if ($tmp === false)
    err(404, 'File or Directory Not Found');
if (substr($tmp, 0, strlen(__DIR__)) !== __DIR__)
    err(403, "Forbidden");

if (!$_COOKIE['_sfm_xsrf'])
    setcookie('_sfm_xsrf', bin2hex(openssl_random_pseudo_bytes(16)));
if ($_POST) {
    if ($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
        err(403, "XSRF Failure");
}

$file = $_REQUEST['file'] ?: '.';
if ($_GET['do'] == 'list') {
    if (is_dir($file)) {
        $directory = $file;
        $result = array();
        $files = array_diff(scandir($directory), array('.', '..'));
        foreach ($files as $entry) {
            $i = $directory . '/' . $entry;
            $stat = stat($i);
            $result[] = array(
                'mtime' => $stat['mtime'],
                'size' => $stat['size'],
                'name' => basename($i),
                'path' => preg_replace('@^\./@', '', $i),
                'is_dir' => is_dir($i),
                'is_deleteable' => (!is_dir($i) && is_writable($directory)) ||
                    (is_dir($i) && is_writable($directory) && is_recursively_deleteable($i)),
                'is_readable' => is_readable($i),
                'is_writable' => is_writable($i),
                'is_executable' => is_executable($i),
            );
        }
    } else {
        err(412, "Not a Directory");
    }
    echo json_encode(array('success' => true, 'is_writable' => is_writable($file), 'results' => $result));
    exit;
} elseif ($_POST['do'] == 'delete') {
    rmrf($file);
    echo json_encode(array('success' => true));
    exit;
} elseif ($_POST['do'] == 'mkdir') {
    chdir($file);
    @mkdir($_POST['name']);
    echo json_encode(array('success' => true));
    exit;
} elseif ($_POST['do'] == 'upload') {
    var_dump($_POST);
    var_dump($_FILES);
    var_dump($_FILES['file_data']['tmp_name']);
    var_dump(move_uploaded_file($_FILES['file_data']['tmp_name'], $file . '/' . $_FILES['file_data']['name']));
    exit;
} elseif ($_GET['do'] == 'download') {
    $filename = basename($file);
    header('Content-Type: ' . mime_content_type($file));
    header('Content-Length: ' . filesize($file));
    header(sprintf('Content-Disposition: attachment; filename=%s',
        strpos('MSIE', $_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\""));
    ob_flush();
    readfile($file);
    exit;
} elseif ($_POST['do'] == 'zip') {
    $filename = basename($file);
    echo $file."\n";
    echo $filename;

    // Initialize archive object
    $zip = new ZipArchive();
    $zip->open($file.".zip", ZipArchive::CREATE | ZipArchive::OVERWRITE);

    // Create recursive directory iterator
    /** @var SplFileInfo[] $files */
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__."/".$file),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $name => $filez)
    {
        // Skip directories (they would be added automatically)
        if (!$filez->isDir())
        {
            // Get real and relative path for current file
            $filePath = $filez->getRealPath();
            $relativePath = substr($filePath, strlen(__DIR__."/".$file) + 1);

            // Add current file to archive
            $zip->addFile($filePath, $relativePath);
        }
    }

    // Zip archive will be created only after closing object
    $zip->close();
    echo json_encode(array('success' => true));
    exit;
}
function rmrf($dir)
{
    if (is_dir($dir)) {
        $files = array_diff(scandir($dir), array('.', '..'));
        foreach ($files as $file)
            rmrf("$dir/$file");
        rmdir($dir);
    } else {
        unlink($dir);
    }
}

function is_recursively_deleteable($d)
{
    $stack = array($d);
    while ($dir = array_pop($stack)) {
        if (!is_readable($dir) || !is_writable($dir))
            return false;
        $files = array_diff(scandir($dir), array('.', '..'));
        foreach ($files as $file) if (is_dir($file)) {
            $stack[] = "$dir/$file";
        }
    }
    return true;
}

function err($code, $msg)
{
    echo json_encode(array('error' => array('code' => intval($code), 'msg' => $msg)));
    exit;
}

function asBytes($ini_v)
{
    $ini_v = trim($ini_v);
    $s = array('g' => 1 << 30, 'm' => 1 << 20, 'k' => 1 << 10);
    return intval($ini_v) * ($s[strtolower(substr($ini_v, -1))] ?: 1);
}

$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <link href="https://maxcdn.bootstrapcdn.com/bootswatch/3.3.4/slate/bootstrap.min.css" rel="stylesheet">
    <style>
        .btn-file {
            position: relative;
            overflow: hidden;
        }

        .btn-file input[type=file] {
            position: absolute;
            top: 0;
            right: 0;
            min-width: 100%;
            min-height: 100%;
            font-size: 100px;
            text-align: right;
            filter: alpha(opacity=0);
            opacity: 0;
            outline: none;
            background: white;
            cursor: inherit;
            display: block;
        }
    </style>
    <script src="https://code.jquery.com/jquery-2.1.4.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
    <script>
        (function ($) {
            $.fn.tablesorter = function () {
                var $table = this;
                this.find('th').click(function () {
                    var idx = $(this).index();
                    var direction = $(this).hasClass('sort_asc');
                    $table.tablesortby(idx, direction);
                });
                return this;
            };
            $.fn.tablesortby = function (idx, direction) {
                var $rows = this.find('tbody tr');

                function elementToVal(a) {
                    var $a_elem = $(a).find('td:nth-child(' + (idx + 1) + ')');
                    var a_val = $a_elem.attr('data-sort') || $a_elem.text();
                    return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
                }

                $rows.sort(function (a, b) {
                    var a_val = elementToVal(a), b_val = elementToVal(b);
                    return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
                })
                this.find('th').removeClass('sort_asc sort_desc');
                $(this).find('thead th:nth-child(' + (idx + 1) + ')').addClass(direction ? 'sort_desc' : 'sort_asc');
                for (var i = 0; i < $rows.length; i++)
                    this.append($rows[i]);
                this.settablesortmarkers();
                return this;
            }
            $.fn.retablesort = function () {
                var $e = this.find('thead th.sort_asc, thead th.sort_desc');
                if ($e.length)
                    this.tablesortby($e.index(), $e.hasClass('sort_desc'));

                return this;
            }
            $.fn.settablesortmarkers = function () {
                this.find('thead th span.indicator').remove();
                this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
                this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
                return this;
            }
        })(jQuery);
        $(function () {
            var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)') || 0)[2];
            var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
            var $tbody = $('#list');
            $(window).bind('hashchange', list).trigger('hashchange');
            $('#table').tablesorter();

            $('body').on('click', '.delete', function (data) {
                $.post("", {'do': 'delete', file: $(this).attr('data-file'), xsrf: XSRF}, function (response) {
                    list();
                }, 'json');
                return false;
            });

            $('body').on('click', '.zip', function (data) {
                $.post("", {'do': 'zip', file: $(this).attr('data-file'), xsrf: XSRF}, function (response) {
                    console.log("weqeqwe");
                    list();
                }, 'json');
                return false;
            });

            $('#mkdir').submit(function (e) {
                var hashval = window.location.hash.substr(1),
                    $dir = $(this).find('[name=name]');
                e.preventDefault();
                $dir.val().length && $.post('?', {
                    'do': 'mkdir',
                    name: $dir.val(),
                    xsrf: XSRF,
                    file: hashval
                }, function (data) {
                    list();
                }, 'json');
                $dir.val('');
                return false;
            });

            // file upload stuff
            $('#file_drop_target').bind('dragover', function () {
                $(this).addClass('drag_over');
                return false;
            }).bind('dragend', function () {
                $(this).removeClass('drag_over');
                return false;
            }).bind('drop', function (e) {
                e.preventDefault();
                var files = e.originalEvent.dataTransfer.files;
                $.each(files, function (k, file) {
                    uploadFile(file);
                });
                $(this).removeClass('drag_over');
            });
            $('input[type=file]').change(function (e) {
                e.preventDefault();
                $.each(this.files, function (k, file) {
                    uploadFile(file);
                });
            });


            function uploadFile(file) {
                var folder = window.location.hash.substr(1);

                if (file.size > MAX_UPLOAD_SIZE) {
                    var $error_row = renderFileSizeErrorRow(file, folder);
                    $('#upload_progress').append($error_row);
                    window.setTimeout(function () {
                        $error_row.fadeOut();
                    }, 5000);
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
                xhr.onload = function () {
                    $row.remove();
                    list();
                };
                xhr.upload.onprogress = function (e) {
                    if (e.lengthComputable) {
                        $row.find('.progress-bar').css('width', (e.loaded / e.total * 100 | 0) + '%');
                    }
                };
                xhr.send(fd);
            }

            function renderFileUploadRow(file, folder) {
                //var $header =
                return $row = $('<div class="panel panel-primary" />')
                    .append('<div class="panel-heading"><h3 class="panel-title" >' + (folder ? folder + '/' : '')
                    + file.name + ' - ' + formatFileSize(file.size) + '</h3></div>')
                    .append($('<div class="progress_track progress progress-striped active" style="margin:0"><div class="progress-bar progress-bar-warning"></div></div>'))
            }

            function renderFileSizeErrorRow(file, folder) {
                return $row = $('<div class="error" />')
                    .append($('<span class="fileuploadname" />').text('Error: ' + (folder ? folder + '/' : '') + file.name))
                    .append($('<span/>').html(' file size - <b>' + formatFileSize(file.size) + '</b>'
                    + ' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>'));
            }

            function list() {
                var hashval = window.location.hash.substr(1);
                $.get('?', {'do': 'list', 'file': hashval}, function (data) {
                    $tbody.empty();
                    renderBreadcrumbs(hashval);
                    if (data.success) {
                        $.each(data.results, function (k, v) {
                            $tbody.append(renderFileRow(v));
                        });
                        !data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td</td>')
                        data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
                    } else {
                        console.warn(data.error.msg);
                    }
                    $('#table').retablesort();
                }, 'json');
            }

            function renderFileRow(data) {
                var $link = $('<a class="name" />')
                    .attr('href', data.is_dir ? '#' + data.path : './' + data.path)
                    .html('<span class="glyphicon '+(data.is_dir ? 'glyphicon-folder-open' : 'glyphicon-file')
                    +'" aria-hidden="true"></span>&nbsp;&nbsp;&nbsp;'+data.name);

                var $zip_link = '<a href="#" data-file="'+data.path+'"  class="zip">' +
                    '<span class="glyphicon glyphicon-briefcase" aria-hidden="true"></span>&nbsp;&nbsp;zip</a>&nbsp;&nbsp;&nbsp;';
                var $dl_link = '<a href="?do=download&file='+encodeURIComponent(data.path)+'">' +
                    '<span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>&nbsp;&nbsp;download</a>&nbsp;&nbsp;&nbsp;';
                var $delete_link = '<a href="#" data-file="'+data.path+'"  class="delete">' +
                    '<span class="glyphicon glyphicon-trash" aria-hidden="true"></span>&nbsp;&nbsp;delete</a>';

                var perms = [];
                if (data.is_readable) perms.push('read');
                if (data.is_writable) perms.push('write');
                if (data.is_executable) perms.push('exec');
                var $html = $('<tr />')
                    .addClass(data.is_dir ? 'is_dir' : '')
                    .append($('<td class="first" />').append($link))
                    .append($('<td/>').attr('data-sort', data.is_dir ? -1 : data.size)
                        .html($('<span class="size" />').text(formatFileSize(data.size))))
                    .append($('<td/>').attr('data-sort', data.mtime).text(formatTimestamp(data.mtime)))
                    .append($('<td/>').text(perms.join('+')))
                    .append($('<td/>').append(data.is_dir ? $zip_link : $dl_link).append(data.is_deleteable ? $delete_link : ''))
                return $html;
            }

            function renderBreadcrumbs(path) {
                var $element = $('#breadcrumb');
                $element.empty();
                var base = "";
                $element.append($('<li><a href=#>Home</a></li>'));
                $.each(path.split('/'), function (k, v) {
                    if (v) {
                        $element.append('<li><a href="#' + base + v + '">' + v + "</a></li>");
                        base += v + '/';
                    }
                });
            }

            function formatTimestamp(unix_timestamp) {
                var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                var d = new Date(unix_timestamp * 1000);
                return [m[d.getMonth()], ' ', d.getDate(), ', ', d.getFullYear(), " ",
                    (d.getHours() % 12 || 12), ":", (d.getMinutes() < 10 ? '0' : '') + d.getMinutes(),
                    " ", d.getHours() >= 12 ? 'PM' : 'AM'].join('');
            }

            function formatFileSize(bytes) {
                var s = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
                for (var pos = 0; bytes >= 1000; pos++, bytes /= 1024);
                var d = Math.round(bytes * 10);
                return pos ? [parseInt(d / 10), ".", d % 10, " ", s[pos]].join('') : bytes + ' bytes';
            }
        })

    </script>
</head>
<body id="file_drop_target">
<nav class="navbar navbar-fixed-top">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar"
                    aria-expanded="false" aria-controls="navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="#">File Manager</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
            <form class="navbar-form navbar-right" action="?" method="post" id="mkdir">
                <div class="form-group">
                    <input type="text" class="form-control" placeholder="Create Folder" id="dirname" name="name">
                </div>
                <button type="submit" class="btn btn-default">Submit</button>
            </form>
            <div class="navbar-form navbar-right">
                <span class="btn btn-default btn-file">
                    Upload File <input type="file" multiple>
                </span>
            </div>
        </div>
    </div>
</nav>
<div class="container-fluid" style="margin-top: 70px;">
    <ul class="breadcrumb" id="breadcrumb"></ul>

    <div id="upload_progress"></div>
    <table id="table" class="table table-striped table-hover">
        <thead>
        <tr>
            <th style='cursor:pointer;'>Name</th>
            <th style='cursor:pointer;'>Size</th>
            <th style='cursor:pointer;'>Modified</th>
            <th style='cursor:pointer;'>Permissions</th>
            <th style='cursor:pointer;'>Actions</th>
        </tr>
        </thead>
        <tbody id="list">

        </tbody>
    </table>
    <footer>simple php filemanager by <a href="https://github.com/jcampbell1">jcampbell1</a> and tweaked by <a href="https://github.com/EduardoOliveira">EduardoOliveira</a> <footer>
</div>
</body>
</html>
