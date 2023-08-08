<?php

#if(!defined('DEBUG')) {define('DEBUG', true);}  # Should not be set in production
if (defined('DEBUG') && DEBUG) {error_reporting(E_ALL); ini_set('display_errors', '1');}

#if(!defined('KEEP_FILES')) {define('KEEP_FILES', true);}  # Should not be set in production
#if(!defined('REMOVE_OLD_FILES')) {define('REMOVE_OLD_FILES', false);}
#if(!defined('REMOVE_OLD_FILES_AGE')) {define('REMOVE_OLD_FILES_AGE', 90);} # If REMOVE_OLD_FILES is defined, how old should the files be when they are removed
#if(!defined('CIPHER')) {define('CIPHER', 'aes-256-cbc');}
#if(!defined('HASHALGO_KEY')) {define('HASHALGO_KEY', 'sha256');}
#if(!defined('HASHALGO_FILE')) {define('HASHALGO_FILE', 'sha256');}
#if(!defined('DEFAULT_PASSWORD_LEN')) {define('DEFAULT_PASSWORD_LEN', 20);}
#if(!defined('TOKEN_LEN')) {define('TOKEN_LEN', 40);}
#if(!defined('MAX_PASSWORD_LEN')) {define('MAX_PASSWORD_LEN', 512);}
#if(!defined('TOKEN_VALIDCHARS')) {define('TOKEN_VALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');}
#if(!defined('PASSWORD_VALIDCHARS')) {define('PASSWORD_VALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_!-');}
#if(!defined('SHRED')) {define('SHRED', true);}
#if(!defined('ENCRYPTED_DIR')) {define('ENCRYPTED_DIR', '../encrypted');}
#if(!defined('HTML_FILE')) {define('HTML_FILE', "../template.local.html");}
#if(!defined('HTML')) {define('HTML', "<html><body>%c%</body></html>");}
#if(!defined('HTML_MAKELINK')) {define('HTML_MAKELINK', "<form action='' method='post'><input type='text' size=50 name='v' value='%v%'><input type='submit' value='Make one-time password link'></form>");}
#if(!defined('HTML_SHOWLINK')) {define('HTML_SHOWLINK', "One time password link:<br><input type='text' size=100 readonly value='%u%'>");}
#if(!defined('HTML_GETPASSWORD')) {define('HTML_GETPASSWORD', "<form action='/t' method='post'><input type='hidden' name='token' value='%t%'><input type='submit' value='Click to get password'></form>");}
#if(!defined('HTML_SHOWPASSWORD')) {define('HTML_SHOWPASSWORD', "This is only shown once, so copy it to somewhere safe<br><input type='text' size=100 readonly value='%v%'>");}
#if(!defined('HTML_NONEXISTING')) {define('HTML_NONEXISTING', "No password found. Maybe the password has already been fetched.");}
