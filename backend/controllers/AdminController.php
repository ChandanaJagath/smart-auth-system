<?php

declare(strict_types=1);

final class AdminController
{
    public function __construct(
        private readonly User $userModel,
        private readonly PDO $pdo
    ) {
    }

    public function listUsers(): void
    {
        AdminMiddleware::requireAdmin($this->pdo);
        $users = $this->userModel->listAllForAdmin();
        $out = [];
        foreach ($users as $u) {
            $out[] = [
                'id' => (int) $u['id'],
                'name' => $u['name'],
                'email' => $u['email'],
                'role' => $u['role'],
                'is_verified' => (int) $u['is_verified'] === 1,
                'created_at' => $u['created_at'],
            ];
        }
        Response::success(['users' => $out]);
    }

    public function deleteUser(): void
    {
        AdminMiddleware::requireAdmin($this->pdo);
        $input = $this->parseJsonBody();
        $targetId = isset($input['user_id']) ? (int) $input['user_id'] : 0;
        $adminId = AuthMiddleware::userId();
        if ($targetId <= 0) {
            Response::error('Invalid user.', 422, 'user_id');
            return;
        }
        if ($adminId !== null && $targetId === $adminId) {
            Response::error('You cannot delete your own account.', 403);
            return;
        }
        $target = $this->userModel->findById($targetId);
        if ($target === null) {
            Response::error('User not found.', 404);
            return;
        }
        if (($target['role'] ?? '') === 'admin') {
            $count = $this->countAdmins();
            if ($count <= 1) {
                Response::error('Cannot delete the last administrator.', 403);
                return;
            }
        }
        $this->userModel->deleteById($targetId);
        Response::success(['message' => 'User deleted.']);
    }

    public function changeRole(): void
    {
        AdminMiddleware::requireAdmin($this->pdo);
        $input = $this->parseJsonBody();
        $targetId = isset($input['user_id']) ? (int) $input['user_id'] : 0;
        $role = Validator::sanitizeString((string) ($input['role'] ?? ''));
        $adminId = AuthMiddleware::userId();

        if ($targetId <= 0) {
            Response::error('Invalid user.', 422, 'user_id');
            return;
        }
        if (!Validator::userRole($role)) {
            Response::error('Role must be user or admin.', 422, 'role');
            return;
        }
        if ($adminId !== null && $targetId === $adminId) {
            Response::error('You cannot change your own role.', 403);
            return;
        }
        $target = $this->userModel->findById($targetId);
        if ($target === null) {
            Response::error('User not found.', 404);
            return;
        }
        if (($target['role'] ?? '') === 'admin' && $role === 'user') {
            $count = $this->countAdmins();
            if ($count <= 1) {
                Response::error('Cannot demote the last administrator.', 403);
                return;
            }
        }
        $this->userModel->updateRole($targetId, $role);
        Response::success(['message' => 'Role updated.']);
    }

    private function countAdmins(): int
    {
        $stmt = $this->pdo->query("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'");
        $row = $stmt->fetch();
        return (int) ($row['c'] ?? 0);
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
}
