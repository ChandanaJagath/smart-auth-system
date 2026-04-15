<?php

declare(strict_types=1);

final class User
{
    public function __construct(
        private readonly PDO $pdo
    ) {
    }

    /**
     * @return int New user id
     */
    public function createUser(
        string $name,
        string $email,
        string $passwordHash,
        string $verificationToken,
        string $verificationExpires,
        string $role = 'user'
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (name, email, password, is_verified, verification_token, verification_expires, role)
             VALUES (:name, :email, :password, 0, :vtoken, :vexpires, :role)'
        );
        $stmt->execute([
            ':name' => $name,
            ':email' => $email,
            ':password' => $passwordHash,
            ':vtoken' => $verificationToken,
            ':vexpires' => $verificationExpires,
            ':role' => $role,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, name, email, password, is_verified, role, created_at FROM users WHERE email = :email LIMIT 1'
        );
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, name, email, is_verified, role, created_at FROM users WHERE id = :id LIMIT 1'
        );
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function findByVerificationToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, verification_expires FROM users WHERE verification_token = :token LIMIT 1'
        );
        $stmt->execute([':token' => $token]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function markEmailVerified(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET is_verified = 1, verification_token = NULL, verification_expires = NULL WHERE id = :id'
        );
        $stmt->execute([':id' => $userId]);
    }

    public function updatePasswordHash(int $userId, string $hash): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
        $stmt->execute([':password' => $hash, ':id' => $userId]);
    }

    public function emailExists(string $email): bool
    {
        return $this->findByEmail($email) !== null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function listAllForAdmin(): array
    {
        $stmt = $this->pdo->query(
            'SELECT id, name, email, is_verified, role, created_at FROM users ORDER BY id ASC'
        );
        return $stmt->fetchAll() ?: [];
    }

    public function deleteById(int $id): bool
    {
        $stmt = $this->pdo->prepare('DELETE FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function updateRole(int $id, string $role): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET role = :role WHERE id = :id');
        $stmt->execute([':role' => $role, ':id' => $id]);
    }

    public function getRole(int $userId): ?string
    {
        $stmt = $this->pdo->prepare('SELECT role FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $userId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return (string) $row['role'];
    }
}
