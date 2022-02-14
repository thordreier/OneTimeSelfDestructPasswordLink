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
if(!defined('TOKEN_LEN')) {define('TOKEN_LEN', 40);}
if(!defined('TOKENVALIDCHARS')) {define('TOKENVALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');}
if(!defined('SHRED')) {define('SHRED', true);}
if(!defined('ENCRYPTED_DIR')) {define('ENCRYPTED_DIR', '../encrypted');}
if(!defined('SECRET_FILE')) {define('SECRET_FILE', '../secret');}
if(!defined('TEXT_MAKELINK')) {define('TEXT_MAKELINK', 'Make one-time password link');}
if(!defined('TEXT_GETPASSWORD')) {define('TEXT_GETPASSWORD', 'Click to get password');}
if(!defined('TEXT_NONEXISTING')) {define('TEXT_NONEXISTING', 'No password found. Maybe the password has already been fetched.');}
if(!defined('DEFAULT_PASSWORD_LEN')) {define('DEFAULT_PASSWORD_LEN', 40);}

if (defined('DEBUG') && DEBUG) {error_reporting(E_ALL); ini_set('display_errors', '1');}


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
        $l = strlen(TOKENVALIDCHARS) - 1;
        $token = '';
        for ($i = 0; $i < $length; $i++) {
            $token .= TOKENVALIDCHARS[random_int(0, $l)];
        }
        return $token;
    }

    public static function createPassword () {
        return self::createToken(DEFAULT_PASSWORD_LEN);
    }

    public static function storeString ($plain) {
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
    return '<html><head><title>Password tool</title></head><body>' . $code . '</body></html>';
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
    $html = "<form action='new' method='post'><input type='text' size=50 name='v' value='$v'><input type='submit' value='".TEXT_MAKELINK."'></form>";
    $html = makeHtml($html);
    $response->getBody()->write($html);
    return $response;
});

$app->post('/new', function (Request $request, Response $response, $args) {
    $data = $request->getParsedBody();
    $v = $data['v'];
    $tokenUri = getTokenUri($v, $request);
    if (preg_match('/application\/json/', $request->getHeaderLine('Content-Type'))) {
        $json = array('uri' => $tokenUri);
        $response = $response->withJson(['uri' => $tokenUri]);
    } else {
        $html = "<input type='text' size=100 readonly value='$tokenUri'>";
        $html = makeHtml($html);
        $response->getBody()->write($html);
    }
    return $response;
});

$app->get('/t/{token}', function (Request $request, Response $response, $args) {
    $token = $args['token'];
    $html = "<form action='/t' method='post'><input type='hidden' name='token' value='$token'><input type='submit' value='".TEXT_GETPASSWORD."'></form>";
    $html = makeHtml($html);
    $response->getBody()->write($html);
    return $response;
});

$app->post('/t', function (Request $request, Response $response, $args) {
    try {
        $data = $request->getParsedBody();
        $token = $data['token'];
        $v = PasswordStore::fetchString($token);
        $html = "This is only shown once, so copy it to somewhere safe<br><input type='text' size=100 readonly value='$v'>";
    } catch(Exception $e) {
        $html = TEXT_NONEXISTING;
    }
    $html = makeHtml($html);
    $response->getBody()->write($html);
    return $response;
});


$app->run();
