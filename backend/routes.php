<?php

declare(strict_types=1);

/**
 * Session-based auth API router.
 * Expects: $_SERVER['REQUEST_METHOD'], $_GET['action']
 */
function route_auth_session(string $action, AuthController $auth, AdminController $admin): void
{
    switch ($action) {
        case 'register':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->register();
            break;
        case 'login':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->login();
            break;
        case 'logout':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->logout();
            break;
        case 'me':
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->me();
            break;
        case 'get_user':
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->me();
            break;
        case 'verify_email':
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->verifyEmail();
            break;
        case 'forgot_password':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->forgotPassword();
            break;
        case 'reset_password':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $auth->resetPassword();
            break;
        case 'admin_users':
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $admin->listUsers();
            break;
        case 'delete_user':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $admin->deleteUser();
            break;
        case 'change_role':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                Response::error('Method not allowed.', 405);
                return;
            }
            $admin->changeRole();
            break;
        default:
            Response::error('Unknown action.', 404);
    }
}
