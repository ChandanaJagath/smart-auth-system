<?php

declare(strict_types=1);

final class Validator
{
    public static function email(string $email): bool
    {
        $email = trim($email);
        if ($email === '') {
            return false;
        }
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function password(string $password): bool
    {
        return strlen($password) >= 6;
    }

    public static function name(string $name): bool
    {
        $name = trim($name);
        return $name !== '' && strlen($name) <= 120;
    }

    /**
     * Strip control chars; keep printable UTF-8 for display.
     */
    public static function sanitizeString(string $value): string
    {
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
        return trim($value);
    }

    /**
     * Hex token from bin2hex(random_bytes(32)) => 64 hex chars.
     */
    public static function hexToken(string $token, int $length = 64): bool
    {
        if (strlen($token) !== $length) {
            return false;
        }
        return ctype_xdigit($token);
    }

    public static function userRole(string $role): bool
    {
        return $role === 'user' || $role === 'admin';
    }
}
