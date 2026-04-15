<?php

declare(strict_types=1);

$envFile = dirname(__DIR__, 2) . '/.env';
if (is_readable($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($lines)) {
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (!str_contains($line, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $k = trim($k);
            $v = trim($v, " \t\n\r\0\x0B\"'");
            if ($k !== '' && getenv($k) === false) {
                putenv($k . '=' . $v);
                $_ENV[$k] = $v;
            }
        }
    }
}

/**
 * Application configuration. Prefer environment variables in production.
 */
return [
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => (int) (getenv('DB_PORT') ?: '3306'),
        'name' => getenv('DB_NAME') ?: 'smart_auth',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
    'app' => [
        'jwt_secret' => getenv('JWT_SECRET') ?: 'change-this-to-a-long-random-secret-in-production',
        'jwt_ttl' => (int) (getenv('JWT_TTL') ?: '3600'),
        /** Base URL to `public/` (no trailing slash). Used in verification and reset links. */
        'public_url' => rtrim((string) (getenv('APP_PUBLIC_URL') ?: 'http://localhost/smart%20auth%20system/public'), '/'),
    ],
    'mail' => [
        'use_mock' => filter_var(getenv('MAIL_USE_MOCK') ?: 'true', FILTER_VALIDATE_BOOLEAN),
        'host' => getenv('MAIL_HOST') ?: '',
        'port' => (int) (getenv('MAIL_PORT') ?: '587'),
        'user' => getenv('MAIL_USER') ?: '',
        'pass' => getenv('MAIL_PASS') ?: '',
        'encryption' => strtolower((string) (getenv('MAIL_ENCRYPTION') ?: 'tls')),
        'from_email' => getenv('MAIL_FROM') ?: (getenv('MAIL_USER') ?: 'noreply@localhost'),
        'from_name' => getenv('MAIL_FROM_NAME') ?: 'Smart Auth',
        /** 0 = off; 1–4 = PHPMailer SMTPDebug (see MailService). */
        'debug' => (int) (getenv('MAIL_DEBUG') ?: '0'),
    ],
];
