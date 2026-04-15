<?php

declare(strict_types=1);

final class AuthMiddleware
{
    public static function requireAuth(): void
    {
        if (empty($_SESSION['user_id'])) {
            Response::error('Authentication required.', 401);
            exit;
        }
    }

    public static function guestOnly(): void
    {
        if (!empty($_SESSION['user_id'])) {
            $role = (string) ($_SESSION['role'] ?? 'user');
            Response::success([
                'message' => 'Already logged in.',
                'redirect' => $role === 'admin' ? 'admin.html' : 'dashboard.html',
                'role' => $role,
            ]);
            exit;
        }
    }

    public static function userId(): ?int
    {
        return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    }
}
