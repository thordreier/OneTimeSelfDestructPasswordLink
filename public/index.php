<?php

#define('DEBUG', true);  # Should not be set in production
define('CIPHER', 'aes-256-cbc');
define('HASHALGO', 'sha256');
define('TOKENLEN', 32);
define('TOKENVALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
define('SHRED', true);
define('PASSWORD_DIR', '../password');
define('SECRET_FILE', '../secret');
define('TEXT_MAKELINK', 'Make one-time password link');
define('TEXT_GETPASSWORD', 'Click to get password');
define('TEXT_NONEXISTING', 'No password found. Maybe the password has already been fetched.');

# Just stop on any error, also warnings
function exception_error_handler($errno, $errstr, $errfile, $errline ) {
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
}
set_error_handler('exception_error_handler');
if (defined('DEBUG') && DEBUG) {error_reporting(E_ALL); ini_set('display_errors', '1');}


use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();


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
        if (SHRED) {exec("shred -n 7 $file");}
        unlink($file);
        return $plain;
    }
}


function makeHtml ($code) {
    return '<html><head><title>Password tool</title></head><body>' . $code . '</body></html>';
}

function getBaseUri ($request) {
    return preg_replace('/^(.+:\/\/[^\/]+)(.*)$/','$1', $request->getUri());
}

function getTokenUri ($v, $request) {
    $baseUri = getBaseUri ($request);
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
    $html = "<input type='text' size=100 readonly value='$tokenUri'>";
    $html = makeHtml($html);
    $response->getBody()->write($html);
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
