<?php

declare(strict_types=1);

/**
 * Stateless JWT register/login (no PHP session).
 */
final class JwtAuthController
{
    public function __construct(
        private readonly User $userModel,
        private readonly JwtService $jwt,
        private readonly MailService $mail
    ) {
    }

    public function register(): void
    {
        $input = $this->parseJsonBody();
        $name = Validator::sanitizeString((string) ($input['name'] ?? ''));
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        if (!Validator::name($name)) {
            Response::error('Please enter a valid name (1–120 characters).', 422, 'name');
            return;
        }
        if (!Validator::email($email)) {
            Response::error('Please enter a valid email address.', 422, 'email');
            return;
        }
        if (!Validator::password($password)) {
            Response::error('Password must be at least 6 characters.', 422, 'password');
            return;
        }
        if ($this->userModel->emailExists($email)) {
            Response::error('An account with this email already exists.', 409, 'email');
            return;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $vToken = bin2hex(random_bytes(32));
        $expires = (new DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');
        $this->userModel->createUser($name, $email, $hash, $vToken, $expires, 'user');

        $sent = $this->mail->sendVerificationEmail($email, $name, $vToken);
        if (!$sent) {
            Response::error('Account created but we could not send the verification email.', 503);
            return;
        }

        Response::success([
            'message' => 'Registration successful. Check your email to verify your account before signing in.',
        ], 201);
    }

    public function login(): void
    {
        $input = $this->parseJsonBody();
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        $ip = $this->clientIp();
        $rateKey = RateLimiter::key($ip, $email);
        if (RateLimiter::isLocked($rateKey)) {
            $sec = RateLimiter::remainingSeconds($rateKey);
            $msg = $sec > 0
                ? 'Too many login attempts. Try again in ' . ceil($sec / 60) . ' minute(s).'
                : 'Too many login attempts. Please try again later.';
            Response::error($msg, 429);
            return;
        }

        if (!Validator::email($email)) {
            Response::error('Please enter a valid email address.', 422, 'email');
            return;
        }
        if ($password === '') {
            Response::error('Password is required.', 422, 'password');
            return;
        }

        $user = $this->userModel->findByEmail($email);
        if ($user === null || !password_verify($password, $user['password'])) {
            RateLimiter::recordFailure($rateKey);
            Response::error('Invalid email or password.', 401);
            return;
        }

        if ((int) ($user['is_verified'] ?? 0) !== 1) {
            RateLimiter::clear($rateKey);
            Response::error('Please verify your email before signing in.', 403);
            return;
        }

        RateLimiter::clear($rateKey);

        $token = $this->jwt->issue((int) $user['id'], $user['email']);

        Response::success([
            'message' => 'Login successful.',
            'token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => $this->jwtTtl(),
            'user' => [
                'id' => (int) $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role'] ?? 'user',
                'is_verified' => ((int) ($user['is_verified'] ?? 0)) === 1,
            ],
        ]);
    }

    public function me(): void
    {
        $claims = $this->bearerClaims();
        if ($claims === null) {
            Response::error('Invalid or expired token.', 401);
            return;
        }
        $user = $this->userModel->findById((int) $claims['sub']);
        if ($user === null) {
            Response::error('User not found.', 404);
            return;
        }
        Response::success([
            'user' => [
                'id' => (int) $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role'] ?? 'user',
                'is_verified' => ((int) ($user['is_verified'] ?? 0)) === 1,
                'created_at' => $user['created_at'],
            ],
        ]);
    }

    private function bearerClaims(): ?array
    {
        $auth = self::authorizationHeader();
        if (!str_starts_with($auth, 'Bearer ')) {
            return null;
        }
        $token = trim(substr($auth, 7));
        if ($token === '') {
            return null;
        }
        return $this->jwt->verify($token);
    }

    private static function authorizationHeader(): string
    {
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            return (string) $_SERVER['HTTP_AUTHORIZATION'];
        }
        if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            return (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        if (function_exists('apache_request_headers')) {
            foreach (apache_request_headers() as $key => $value) {
                if (strcasecmp((string) $key, 'Authorization') === 0) {
                    return (string) $value;
                }
            }
        }
        return '';
    }

    private function parseJsonBody(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
        }
        try {
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            return is_array($data) ? $data : [];
        } catch (JsonException) {
            return [];
        }
    }

    private function clientIp(): string
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($parts[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function jwtTtl(): int
    {
        $config = require dirname(__DIR__) . '/config/config.php';
        return (int) $config['app']['jwt_ttl'];
    }
}
