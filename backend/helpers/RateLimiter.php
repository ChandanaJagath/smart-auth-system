<?php

declare(strict_types=1);

/**
 * Simple file-based rate limiter for login attempts (per IP + identifier).
 */
final class RateLimiter
{
    private const MAX_ATTEMPTS = 5;
    private const WINDOW_SECONDS = 900; // 15 minutes

    public static function storageDir(): string
    {
        $dir = dirname(__DIR__) . '/storage/ratelimit';
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
                $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'smart_auth_ratelimit';
                if (!is_dir($dir)) {
                    @mkdir($dir, 0700, true);
                }
            }
        }
        return $dir;
    }

    public static function key(string $ip, string $email): string
    {
        return hash('sha256', $ip . '|' . strtolower($email));
    }

    public static function isLocked(string $key): bool
    {
        $file = self::storageDir() . '/' . $key . '.json';
        if (!is_file($file)) {
            return false;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return false;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return false;
        }
        $count = (int) ($data['count'] ?? 0);
        $first = (int) ($data['first'] ?? 0);
        if ($count >= self::MAX_ATTEMPTS && (time() - $first) < self::WINDOW_SECONDS) {
            return true;
        }
        if ((time() - $first) >= self::WINDOW_SECONDS) {
            @unlink($file);
            return false;
        }
        return false;
    }

    public static function recordFailure(string $key): void
    {
        $dir = self::storageDir();
        if (!is_dir($dir) || !is_writable($dir)) {
            return;
        }
        $file = $dir . '/' . $key . '.json';
        $now = time();
        $data = ['count' => 1, 'first' => $now];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            $prev = json_decode((string) $raw, true);
            if (is_array($prev)) {
                $first = (int) ($prev['first'] ?? $now);
                if (($now - $first) >= self::WINDOW_SECONDS) {
                    $data = ['count' => 1, 'first' => $now];
                } else {
                    $data = [
                        'count' => (int) ($prev['count'] ?? 0) + 1,
                        'first' => $first,
                    ];
                }
            }
        }
        @file_put_contents($file, json_encode($data), LOCK_EX);
    }

    public static function clear(string $key): void
    {
        $file = self::storageDir() . '/' . $key . '.json';
        if (is_file($file)) {
            @unlink($file);
        }
    }

    public static function remainingSeconds(string $key): int
    {
        $file = self::storageDir() . '/' . $key . '.json';
        if (!is_file($file)) {
            return 0;
        }
        $raw = @file_get_contents($file);
        $data = json_decode((string) $raw, true);
        if (!is_array($data)) {
            return 0;
        }
        $first = (int) ($data['first'] ?? 0);
        $elapsed = time() - $first;
        $rem = self::WINDOW_SECONDS - $elapsed;
        return $rem > 0 ? $rem : 0;
    }
}
