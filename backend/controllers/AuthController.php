<?php

declare(strict_types=1);

final class AuthController
{
    public function __construct(
        private readonly User $userModel,
        private readonly PDO $pdo,
        private readonly PasswordReset $passwordReset,
        private readonly MailService $mail,
        private readonly string $publicUrl
    ) {
    }

    public function register(): void
    {
        AuthMiddleware::guestOnly();

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
        $token = bin2hex(random_bytes(32));
        $expires = (new DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');

        $this->userModel->createUser($name, $email, $hash, $token, $expires, 'user');

        $sent = $this->mail->sendVerificationEmail($email, $name, $token);
        if (!$sent) {
            Response::error('Account created but we could not send the verification email. Contact support.', 503);
            return;
        }

        Response::success([
            'message' => 'Registration successful. Check your email to verify your account before signing in.',
            'redirect' => 'index.html',
        ], 201);
    }

    public function verifyEmail(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            Response::error('Method not allowed.', 405);
            return;
        }
        $token = (string) ($_GET['token'] ?? '');
        if (!Validator::hexToken($token, 64)) {
            Response::error('Invalid or expired verification link.', 400);
            return;
        }
        $user = $this->userModel->findByVerificationToken($token);
        if ($user === null) {
            Response::error('Invalid or expired verification link.', 400);
            return;
        }
        $expires = $user['verification_expires'] ?? null;
        if ($expires === null || $expires === '') {
            Response::error('Invalid or expired verification link.', 400);
            return;
        }
        if (self::isExpiredAt((string) $expires)) {
            Response::error('This verification link has expired. Please register again or contact support.', 410);
            return;
        }
        $this->userModel->markEmailVerified((int) $user['id']);
        Response::success([
            'message' => 'Your email has been verified. You can sign in now.',
            'redirect' => 'index.html',
        ]);
    }

    public function login(): void
    {
        AuthMiddleware::guestOnly();

        $input = $this->parseJsonBody();
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');
        $remember = !empty($input['remember']);

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
            Response::error('Please verify your email before signing in. Check your inbox for the verification link.', 403);
            return;
        }

        RateLimiter::clear($rateKey);

        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $user['id'];
        $role = (string) ($user['role'] ?? 'user');
        $_SESSION['role'] = $role;

        if ($remember) {
            RememberMe::create($this->pdo, (int) $user['id']);
        } else {
            RememberMe::clearCookie();
        }

        Response::success([
            'message' => 'Login successful.',
            'role' => $role,
            'redirect' => $role === 'admin' ? 'admin.html' : 'dashboard.html',
            'user' => [
                'id' => (int) $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $role,
                'is_verified' => ((int) ($user['is_verified'] ?? 0)) === 1,
            ],
        ]);
    }

    public function forgotPassword(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            Response::error('Method not allowed.', 405);
            return;
        }
        $ip = $this->clientIp();
        $rateKey = 'forgot:' . $ip;
        if (RateLimiter::isLocked($rateKey)) {
            Response::error('Too many requests. Please try again later.', 429);
            return;
        }

        $input = $this->parseJsonBody();
        if (($input['email'] ?? '') === '' && isset($_POST['email']) && is_string($_POST['email'])) {
            $input['email'] = $_POST['email'];
        }

        $email = strtolower(trim((string) ($input['email'] ?? '')));
        if (!Validator::email($email)) {
            Response::error('Please enter a valid email address.', 422, 'email');
            return;
        }

        RateLimiter::recordFailure($rateKey);

        $user = $this->userModel->findByEmail($email);
        if ($user === null) {
            Response::success([
                'message' => 'If an account exists for that email, we sent password reset instructions.',
                'reset_link' => null,
            ]);
            return;
        }

        $token = bin2hex(random_bytes(32));
        $expires = (new DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');

        try {
            $this->passwordReset->create($email, $token, $expires);
        } catch (Throwable $e) {
            error_log('[smart-auth] forgot_password db: ' . $e->getMessage());
            Response::error('Unable to process reset request. Please try again later.', 503);
            return;
        }

        /* Dev/testing: return reset link in JSON (matches APP_PUBLIC_URL so reset.html loads the same app). */
        $base = rtrim($this->publicUrl, '/');
        $resetLink = $base . '/reset.html?token=' . rawurlencode($token);
        Response::success([
            'message' => 'Reset link generated. Open it on this site to set a new password.',
            'reset_link' => $resetLink,
        ]);
    }

    public function resetPassword(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            Response::error('Method not allowed.', 405);
            return;
        }
        $input = $this->parseJsonBody();
        if (($input['token'] ?? '') === '' && isset($_POST['token']) && is_string($_POST['token'])) {
            $input['token'] = $_POST['token'];
        }
        if (($input['password'] ?? '') === '' && isset($_POST['password']) && is_string($_POST['password'])) {
            $input['password'] = $_POST['password'];
        }
        $token = strtolower(trim((string) ($input['token'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        if (!Validator::hexToken($token, 64)) {
            Response::error('Invalid or expired reset link.', 400);
            return;
        }
        if (!Validator::password($password)) {
            Response::error('Password must be at least 6 characters.', 422, 'password');
            return;
        }

        $row = $this->passwordReset->findValidByToken($token);
        if ($row === null) {
            Response::error('Invalid or expired reset link.', 400);
            return;
        }
        $expires = (string) ($row['expires_at'] ?? '');
        if (self::isExpiredAt($expires)) {
            $this->passwordReset->deleteByToken($token);
            Response::error('This reset link has expired. Please request a new one.', 410);
            return;
        }

        $email = strtolower((string) $row['email']);
        $user = $this->userModel->findByEmail($email);
        if ($user === null) {
            $this->passwordReset->deleteByToken($token);
            Response::error('Invalid reset link.', 400);
            return;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $this->userModel->updatePasswordHash((int) $user['id'], $hash);
        $this->passwordReset->deleteByToken($token);

        RememberMe::deleteAllForUser($this->pdo, (int) $user['id']);

        Response::success([
            'message' => 'Your password has been reset. You can sign in now.',
            'redirect' => 'index.html',
        ]);
    }

    public function logout(): void
    {
        $uid = AuthMiddleware::userId();
        if ($uid !== null) {
            RememberMe::deleteAllForUser($this->pdo, $uid);
        }
        RememberMe::clearCookie();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $p['path'],
                'domain' => $p['domain'] ?? '',
                'secure' => $p['secure'],
                'httponly' => $p['httponly'],
                'samesite' => $p['samesite'] ?? 'Lax',
            ]);
        }
        session_destroy();
        session_start();
        session_regenerate_id(true);

        Response::success(['message' => 'Logged out.', 'redirect' => 'index.html']);
    }

    public function me(): void
    {
        AuthMiddleware::requireAuth();

        $uid = AuthMiddleware::userId();
        if ($uid === null) {
            return;
        }
        $user = $this->userModel->findById($uid);
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

    private static function isExpiredAt(string $expires): bool
    {
        if ($expires === '') {
            return true;
        }
        $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $expires)
            ?: DateTimeImmutable::createFromFormat('Y-m-d H:i:s', substr($expires, 0, 19));
        if ($dt !== false) {
            return $dt < new DateTimeImmutable('now');
        }
        $ts = strtotime($expires);
        if ($ts === false) {
            return true;
        }
        return $ts < time();
    }
}
