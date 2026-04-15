<?php

declare(strict_types=1);

$base = dirname(__DIR__, 2) . '/backend';

$autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';
if (is_readable($autoload)) {
    require_once $autoload;
}

require_once $base . '/config/db.php';
require_once $base . '/helpers/Response.php';
require_once $base . '/helpers/Validator.php';
require_once $base . '/helpers/RateLimiter.php';
require_once $base . '/helpers/RememberMe.php';
require_once $base . '/helpers/MailService.php';
require_once $base . '/models/User.php';
require_once $base . '/models/PasswordReset.php';
require_once $base . '/middleware/AuthMiddleware.php';
require_once $base . '/middleware/AdminMiddleware.php';
require_once $base . '/controllers/AuthController.php';
require_once $base . '/controllers/AdminController.php';
require_once $base . '/routes.php';

$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

$pdo = Database::getConnection();

/* Must not take down JSON API if remember_tokens is missing or DB hiccups */
try {
    RememberMe::tryRestoreSession($pdo);
} catch (Throwable $e) {
    error_log('[smart-auth] remember_me restore skipped: ' . $e->getMessage());
}

$config = require $base . '/config/config.php';
$mail = new MailService($config['mail'], $config['app']['public_url']);

$userModel = new User($pdo);
$passwordReset = new PasswordReset($pdo);

if (!empty($_SESSION['user_id']) && empty($_SESSION['role'])) {
    $sessionUser = $userModel->findById((int) $_SESSION['user_id']);
    if ($sessionUser !== null) {
        $_SESSION['role'] = (string) ($sessionUser['role'] ?? 'user');
    }
}

$auth = new AuthController($userModel, $pdo, $passwordReset, $mail, $config['app']['public_url']);
$admin = new AdminController($userModel, $pdo);

$action = $_GET['action'] ?? '';
if ($action === '') {
    Response::error('Missing action.', 400);
    exit;
}

try {
    route_auth_session($action, $auth, $admin);
} catch (Throwable $e) {
    error_log('[smart-auth] ' . $e->getMessage());
    Response::error('Something went wrong. Please try again.', 500);
}
