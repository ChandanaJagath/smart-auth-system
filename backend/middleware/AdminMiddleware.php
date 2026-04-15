<?php

declare(strict_types=1);

final class AdminMiddleware
{
    public static function requireAdmin(PDO $pdo): void
    {
        AuthMiddleware::requireAuth();
        $uid = AuthMiddleware::userId();
        if ($uid === null) {
            return;
        }
        $stmt = $pdo->prepare('SELECT role FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $uid]);
        $row = $stmt->fetch();
        if ($row === false || ($row['role'] ?? '') !== 'admin') {
            Response::error('Forbidden.', 403);
            exit;
        }
    }
}
