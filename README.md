simple-file-manager
===================

A Simple PHP file manager.  The code is a single php file.  

Just copy `index.php` to a folder on your webserver.  

## Why it is good

- Single file, there are no images, or css folders.  
- Ajax based so it is fast, but doesn't break the back button
- Allows drag and drop file uploads if the folder is writable by the webserver (`chmod 777 your/folder`)
- Suits my aesthetics.  More like Dropbox, and less like Windows Explorer
- Works with Unicode file names
- The interface is usable from an iPad
- XSRF protection, and an optional password.
- Allows to write to files, even possible to modify php files read from server

## Do not allow uploads on the public web

If you allow uploads on the public web, it is only a matter of time before your server is hosting and serving very illegal content. Any of the following options will prevent this:
 - Don't make the folder writable by the webserver `chmod 775`
 - Set `$allow_upload = false`
 - Use a password `$PASSWORD = 'some password'`
 - Use a `.htaccess` file with Apache, or `auth_basic` for nginx
 - Only use this on a private network

HT: [@beardog108](https://github.com/beardog108)

## Forks

- **Edit feature**. An extension of the initial project which lets you edit files and save them from the main php file. Works asynchronously with ajax requests. Link: [@diego95root](https://github.com/diego95root/File-manager-php)

## Screenshot

![Screenshot](https://github.com/diego95root/simple-file-manager/blob/editable/screenshotD.png?raw=true "Screenshot")
