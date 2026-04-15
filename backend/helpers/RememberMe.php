<?php

declare(strict_types=1);

/**
 * Secure remember-me using selector + hashed validator stored in DB.
 */
final class RememberMe
{
    private const COOKIE_NAME = 'smart_auth_remember';
    private const DAYS = 30;

    public static function cookieName(): string
    {
        return self::COOKIE_NAME;
    }

    public static function create(PDO $pdo, int $userId): void
    {
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $validator);
        $expires = (new DateTimeImmutable('+' . self::DAYS . ' days'))->format('Y-m-d H:i:s');

        $stmt = $pdo->prepare(
            'INSERT INTO remember_tokens (user_id, selector, token_hash, expires_at) VALUES (:uid, :sel, :th, :exp)'
        );
        $stmt->execute([
            ':uid' => $userId,
            ':sel' => $selector,
            ':th' => $tokenHash,
            ':exp' => $expires,
        ]);

        $cookieValue = $selector . ':' . $validator;
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $params = [
            'expires' => time() + (self::DAYS * 86400),
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ];
        setcookie(self::COOKIE_NAME, $cookieValue, $params);
    }

    public static function clearCookie(): void
    {
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        setcookie(self::COOKIE_NAME, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    public static function tryRestoreSession(PDO $pdo): void
    {
        if (!empty($_SESSION['user_id'])) {
            return;
        }
        $raw = $_COOKIE[self::COOKIE_NAME] ?? '';
        if ($raw === '' || !str_contains($raw, ':')) {
            return;
        }
        [$selector, $validator] = explode(':', $raw, 2);
        if (strlen($selector) !== 32 || strlen($validator) !== 64) {
            self::clearCookie();
            return;
        }

        $stmt = $pdo->prepare(
            'SELECT id, user_id, token_hash, expires_at FROM remember_tokens WHERE selector = :s LIMIT 1'
        );
        $stmt->execute([':s' => $selector]);
        $row = $stmt->fetch();
        if (!$row) {
            self::clearCookie();
            return;
        }
        if ($row['expires_at'] < (new DateTimeImmutable('now'))->format('Y-m-d H:i:s')) {
            self::deleteBySelector($pdo, $selector);
            self::clearCookie();
            return;
        }
        $calc = hash('sha256', $validator);
        if (!hash_equals($row['token_hash'], $calc)) {
            self::deleteBySelector($pdo, $selector);
            self::clearCookie();
            return;
        }

        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $row['user_id'];

        // Rotate token
        self::deleteBySelector($pdo, $selector);
        self::create($pdo, (int) $row['user_id']);
    }

    public static function deleteAllForUser(PDO $pdo, int $userId): void
    {
        $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE user_id = :id');
        $stmt->execute([':id' => $userId]);
    }

    private static function deleteBySelector(PDO $pdo, string $selector): void
    {
        $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE selector = :s');
        $stmt->execute([':s' => $selector]);
    }
}
