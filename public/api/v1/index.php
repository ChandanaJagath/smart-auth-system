<?php

declare(strict_types=1);

/**
 * JWT API (stateless). Use Authorization: Bearer <token> for /me.
 * Web root should be `public/` (same depth as public/api/index.php).
 */
$root = dirname(__DIR__, 3);
$base = $root . '/backend';

$autoload = $root . '/vendor/autoload.php';
if (is_readable($autoload)) {
    require_once $autoload;
}

require_once $base . '/config/config.php';
require_once $base . '/config/db.php';
require_once $base . '/helpers/Response.php';
require_once $base . '/helpers/Validator.php';
require_once $base . '/helpers/RateLimiter.php';
require_once $base . '/helpers/MailService.php';
require_once $base . '/helpers/JwtService.php';
require_once $base . '/models/User.php';
require_once $base . '/controllers/JwtAuthController.php';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$config = require $base . '/config/config.php';
$secret = (string) $config['app']['jwt_secret'];
$ttl = (int) $config['app']['jwt_ttl'];
$jwt = new JwtService($secret, $ttl);
$mail = new MailService($config['mail'], $config['app']['public_url']);

$pdo = Database::getConnection();
$userModel = new User($pdo);
$auth = new JwtAuthController($userModel, $jwt, $mail);

$action = $_GET['action'] ?? '';
if ($action === '') {
    Response::error('Missing action.', 400);
    exit;
}

try {
    switch ($action) {
        case 'register':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                break;
            }
            $auth->register();
            break;
        case 'login':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                break;
            }
            $auth->login();
            break;
        case 'me':
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                Response::error('Method not allowed.', 405);
                break;
            }
            $auth->me();
            break;
        default:
            Response::error('Unknown action.', 404);
    }
} catch (Throwable $e) {
    error_log('[smart-auth-jwt] ' . $e->getMessage());
    Response::error('Something went wrong. Please try again.', 500);
}
