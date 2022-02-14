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
if(!defined('HASHALGO')) {define('HASHALGO', 'sha256');}
if(!defined('TOKENLEN')) {define('TOKENLEN', 32);}
if(!defined('TOKENVALIDCHARS')) {define('TOKENVALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');}
if(!defined('SHRED')) {define('SHRED', true);}
if(!defined('PASSWORD_DIR')) {define('PASSWORD_DIR', '../password');}
if(!defined('SECRET_FILE')) {define('SECRET_FILE', '../secret');}
if(!defined('TEXT_MAKELINK')) {define('TEXT_MAKELINK', 'Make one-time password link');}
if(!defined('TEXT_GETPASSWORD')) {define('TEXT_GETPASSWORD', 'Click to get password');}
if(!defined('TEXT_NONEXISTING')) {define('TEXT_NONEXISTING', 'No password found. Maybe the password has already been fetched.');}


if (defined('DEBUG') && DEBUG) {error_reporting(E_ALL); ini_set('display_errors', '1');}


use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
require __DIR__ . '/../vendor/autoload.php';
$app = AppFactory::create();
if (defined('DEBUG') && DEBUG) {$app->addErrorMiddleware(true, true, true);}


class PasswordStore {

    private static $secret = null;

    public static function getSecret () {
        if (! self::$secret) {
            self::$secret = base64_decode(file_get_contents(SECRET_FILE));
            if (strlen(self::$secret) != 96) {throw new Exception('Secret does not have correct length');}
        }
        return self::$secret;
    }

    public static function getIV () {
        return substr(self::getSecret(), 0, openssl_cipher_iv_length(CIPHER));
    }

    public static function getHashKey () {
        return substr(self::getSecret(), 64);
    }

    public static function encryptString ($plain, $key) {
        return openssl_encrypt($plain, CIPHER, $key, 0, self::getIV());
    }

    public static function decryptString ($encrypted, $key) {
        return openssl_decrypt($encrypted, CIPHER, $key, 0, self::getIV());
    }

    public static function hashString ($plain) {
        return hash_hmac(HASHALGO, $plain, self::getHashKey());
    }

    public static function createToken ($length = TOKENLEN) {
        $l = strlen(TOKENVALIDCHARS) - 1;
        $token = '';
        for ($i = 0; $i < $length; $i++) {
            $token .= TOKENVALIDCHARS[random_int(0, $l)];
        }
        return $token;
    }

    public static function createPassword () {
        return self::createToken(20);
    }

    public static function storeString ($plain) {
        $token = self::createToken();
        $tokenHash = self::hashString($token);
        $encrypted = self::encryptString($plain, $token);
        $file = PASSWORD_DIR . '/' . $tokenHash;
        umask(0077);
        file_put_contents($file, $encrypted);
        return $token;
    }

    public static function fetchString ($token) {
        if (strlen($token) != TOKENLEN) {throw new Exception('Token does not have correct length');}
        $tokenHash = self::hashString($token);
        $file = PASSWORD_DIR . '/' . $tokenHash;
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
