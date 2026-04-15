<?php

declare(strict_types=1);

final class PasswordReset
{
    public function __construct(
        private readonly PDO $pdo
    ) {
    }

    public function deleteByEmail(string $email): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM password_resets WHERE email = :email');
        $stmt->execute([':email' => $email]);
    }

    public function create(string $email, string $token, string $expiresAt): void
    {
        $this->deleteByEmail($email);
        $stmt = $this->pdo->prepare(
            'INSERT INTO password_resets (email, token, expires_at) VALUES (:email, :token, :expires_at)'
        );
        $stmt->execute([
            ':email' => $email,
            ':token' => $token,
            ':expires_at' => $expiresAt,
        ]);
    }

    public function findValidByToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, token, expires_at FROM password_resets WHERE token = :token LIMIT 1'
        );
        $stmt->execute([':token' => $token]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function deleteByToken(string $token): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM password_resets WHERE token = :token');
        $stmt->execute([':token' => $token]);
    }
}
