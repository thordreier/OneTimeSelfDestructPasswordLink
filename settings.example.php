<?php

#define('DEBUG', true);  # Should not be set in production
#define('KEEP_FILES', true);  # Should not be set in production
#define('CIPHER', 'aes-256-cbc');
#define('HASHALGO_KEY', 'sha256');
#define('HASHALGO_FILE', 'sha256');
#define('TOKENLEN', 40);
#define('TOKENVALIDCHARS', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
#define('SHRED', true);
#define('ENCRYPTED_DIR', '../encrypted');
#define('SECRET_FILE', '../secret');
#define('TEXT_MAKELINK', 'Make one-time password link');
#define('TEXT_GETPASSWORD', 'Click to get password');
#define('TEXT_NONEXISTING', 'No password found. Maybe the password has already been fetched.');
#define('DEFAULT_PASSWORD_LEN', 5);
