<?php

declare(strict_types=1);

final class Response
{
    public static function json(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    }

    public static function error(string $message, int $statusCode = 400, ?string $field = null): void
    {
        $payload = [
            'success' => false,
            'message' => $message,
        ];
        if ($field !== null) {
            $payload['field'] = $field;
        }
        self::json($payload, $statusCode);
    }

    public static function success(array $data = [], int $statusCode = 200): void
    {
        self::json(array_merge(['success' => true], $data), $statusCode);
    }
}
