<?php

# Just stop on any error, also warnings
function exception_error_handler($errno, $errstr, $errfile, $errline ) {
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
}
set_error_handler('exception_error_handler');


define('SETTINGS_LOCAL', '../settings.local.php');
if (file_exists(SETTINGS_LOCAL)) {
    require_once(SETTINGS_LOCAL);
}


#if(!defined('DEBUG')) {define('DEBUG', true);}  # Should not be set in production
#if(!defined('KEEP_FILES')) {define('KEEP_FILES', true);}  # Should not be set in production
if(!defined('CIPHER')) {define('CIPHER', 'aes-256-cbc');}
if(!defined('HASHALGO_KEY')) {define('HASHALGO_KEY', 'sha256');}
if(!defined('HASHALGO_FILE')) {define('HASHALGO_FILE', 'sha256');}
if(!defined('DEFAULT_PASSWORD_LEN')) {define('DEFAULT_PASSWORD_LEN', 20);}
if(!defined('MAX_PASSWORD_LEN')) {define('MAX_PASSWORD_LEN', 512);}
if(!defined('TOKEN_LEN')) {define('TOKEN_LEN', 40);}
if(!defined('TOKEN_VALIDCHARS')) {define('TOKEN_VALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/!$');}
if(!defined('SHRED')) {define('SHRED', true);}
if(!defined('ENCRYPTED_DIR')) {define('ENCRYPTED_DIR', '../encrypted');}
if(!defined('SECRET_FILE')) {define('SECRET_FILE', '../secret');}
if(!defined('HTML_FILE')) {define('HTML_FILE', "../template.local.html");}
if(!defined('HTML')) {define('HTML', "<html><body>%c%</body></html>");}
if(!defined('HTML_MAKELINK')) {define('HTML_MAKELINK', "<form action='' method='post'><input type='text' size=50 name='v' value='%v%'><input type='submit' value='Make one-time password link'></form>");}
if(!defined('HTML_SHOWLINK')) {define('HTML_SHOWLINK', "One time password link:<br><input type='text' size=100 readonly value='%u%'>");}
if(!defined('HTML_GETPASSWORD')) {define('HTML_GETPASSWORD', "<form action='/t' method='post'><input type='hidden' name='token' value='%t%'><input type='submit' value='Click to get password'></form>");}
if(!defined('HTML_SHOWPASSWORD')) {define('HTML_SHOWPASSWORD', "This is only shown once, so copy it to somewhere safe<br><input type='text' size=100 readonly value='%v%'>");}
if(!defined('HTML_NONEXISTING')) {define('HTML_NONEXISTING', "No password found. Maybe the password has already been fetched.");}


use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
require __DIR__ . '/../vendor/autoload.php';
$app = AppFactory::create();
if (defined('DEBUG') && DEBUG) {$app->addErrorMiddleware(true, true, true);}


class PasswordStore {
    public static function encryptString ($plain, $key) {
        $saltLen = strlen(hash(HASHALGO_KEY, '', true));
        $ivLen = openssl_cipher_iv_length(CIPHER);
        $salt = openssl_random_pseudo_bytes($saltLen);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $hashedKey = hash_hmac(HASHALGO_KEY, $key, $salt);
        $raw = openssl_encrypt($plain, CIPHER, $hashedKey, OPENSSL_RAW_DATA, $iv);
        return base64_encode($salt.$iv.$raw);
    }

    public static function decryptString ($encrypted, $key) {
        $binary = base64_decode($encrypted);
        $saltLen = strlen(hash(HASHALGO_KEY, '', true));
        $ivLen = openssl_cipher_iv_length(CIPHER);
        $salt = substr($binary, 0, $saltLen);
        $iv = substr($binary, $saltLen, $ivLen);
        $raw = substr($binary, $saltLen+$ivLen);
        $hashedKey = hash_hmac(HASHALGO_KEY, $key, $salt);
        return openssl_decrypt($raw, CIPHER, $hashedKey, true, $iv);
    }

    public static function hashFileName ($plain) {
        return hash(HASHALGO_FILE, $plain);
    }

    public static function createToken ($length = TOKEN_LEN) {
        $l = strlen(TOKEN_VALIDCHARS) - 1;
        $token = '';
        for ($i = 0; $i < $length; $i++) {
            $token .= TOKEN_VALIDCHARS[random_int(0, $l)];
        }
        return $token;
    }

    public static function createPassword () {
        return self::createToken(DEFAULT_PASSWORD_LEN);
    }

    public static function storeString ($plain) {
        if (strlen($plain) > MAX_PASSWORD_LEN) {throw new Exception('Password is longer than allowed');}
        $token = self::createToken();
        $encrypted = self::encryptString($plain, $token);
        $file = ENCRYPTED_DIR . '/' . self::hashFileName($token);
        umask(0077);
        file_put_contents($file, $encrypted);
        return $token;
    }

    public static function fetchString ($token) {
        if (strlen($token) != TOKEN_LEN) {throw new Exception('Token does not have correct length');}
        $file = ENCRYPTED_DIR . '/' . self::hashFileName($token);
        $encrypted = file_get_contents($file);
        $plain = self::decryptString($encrypted, $token);
        if (! defined('KEEP_FILES') || ! DEBUG) {
            if (SHRED) {exec("shred -n 7 $file");}
            unlink($file);
        }
        return $plain;
    }
}


function makeHtml ($code) {
    if (file_exists(HTML_FILE)) {
        $html = file_get_contents(HTML_FILE);
    } else {
        $html = HTML;
    }
    return str_replace('%c%', $code, $html);
    #return '<html><head><title>Password tool</title></head><body>' . $code . '</body></html>';
}

function getBaseUri ($request) {
    # For some reason uri doen't get blessed with slim/http/src/Uri.php
    # Just implementing the same stuff in here
    $scheme = $request->getUri()->getScheme();
    $authority = $request->getUri()->getAuthority();
    return ($scheme !== '' ? $scheme . ':' : '') . ($authority !== '' ? '//' . $authority : '');
}

function getTokenUri ($v, $request) {
    $baseUri = getBaseUri($request);
    $token = PasswordStore::storeString($v);
    return "$baseUri/t/$token";
}

$app->get('/', function (Request $request, Response $response, $args) {
    $v = PasswordStore::createPassword();
    $html = makeHtml(str_replace('%v%', $v, HTML_MAKELINK));
    $response->getBody()->write($html);
    return $response;
});

$app->post('/', function (Request $request, Response $response, $args) {
    $data = $request->getParsedBody();
    if ($request->getContentType() == 'application/json') {
        $json = array();
        if (isset($data['generate']) && $data['generate']) {
            $v = PasswordStore::createPassword();
            $json['v'] = $v;
        } else {
            $v = $data['v'];
        }
        $json['uri'] = getTokenUri($v, $request);
        $response = $response->withJson($json);
    } else {
        $v = $data['v'];
        $tokenUri = getTokenUri($v, $request);
        $html = makeHtml(str_replace('%u%', $tokenUri, HTML_SHOWLINK));
        $response->getBody()->write($html);
    }
    return $response;
});

$app->get('/t/{token}', function (Request $request, Response $response, $args) {
    $token = $args['token'];
    $html = makeHtml(str_replace('%t%', $token, HTML_GETPASSWORD));
    $response->getBody()->write($html);
    return $response;
});

$app->post('/t', function (Request $request, Response $response, $args) {
    try {
        $data = $request->getParsedBody();
        $token = $data['token'];
        $v = PasswordStore::fetchString($token);
        $html = str_replace('%v%', $v, HTML_SHOWPASSWORD);
    } catch(Exception $e) {
        $html = HTML_NONEXISTING;
    }
    $html = makeHtml($html);
    $response->getBody()->write($html);
    return $response;
});


$app->run();
