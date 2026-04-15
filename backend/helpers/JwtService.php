<?php

declare(strict_types=1);

/**
 * Minimal HS256 JWT create/verify (no external dependencies).
 */
final class JwtService
{
    public function __construct(
        private readonly string $secret,
        private readonly int $ttlSeconds
    ) {
    }

    public function issue(int $userId, string $email): string
    {
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        $now = time();
        $payload = [
            'sub' => $userId,
            'email' => $email,
            'iat' => $now,
            'exp' => $now + $this->ttlSeconds,
        ];
        $h = $this->b64url(json_encode($header, JSON_THROW_ON_ERROR));
        $p = $this->b64url(json_encode($payload, JSON_THROW_ON_ERROR));
        $sig = $this->sign($h . '.' . $p);
        return $h . '.' . $p . '.' . $sig;
    }

    /**
     * @return array{sub:int,email:string,iat:int,exp:int}|null
     */
    public function verify(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        [$h, $p, $sig] = $parts;
        $expected = $this->sign($h . '.' . $p);
        if (!hash_equals($expected, $sig)) {
            return null;
        }
        $payload = json_decode($this->b64urlDecode($p), true);
        if (!is_array($payload)) {
            return null;
        }
        $exp = (int) ($payload['exp'] ?? 0);
        if ($exp < time()) {
            return null;
        }
        $sub = (int) ($payload['sub'] ?? 0);
        if ($sub <= 0) {
            return null;
        }
        return [
            'sub' => $sub,
            'email' => (string) ($payload['email'] ?? ''),
            'iat' => (int) ($payload['iat'] ?? 0),
            'exp' => $exp,
        ];
    }

    private function sign(string $data): string
    {
        $raw = hash_hmac('sha256', $data, $this->secret, true);
        return $this->b64url($raw);
    }

    private function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function b64urlDecode(string $data): string
    {
        $b64 = strtr($data, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad > 0) {
            $b64 .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($b64, true);
        return $out === false ? '' : $out;
    }
}
