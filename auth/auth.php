<?php
declare(strict_types=1);

final class Auth
{
    public static function attempt(string $username, string $password): bool
    {
        $stmt = DB::conn()->prepare("
            SELECT id, password_hash
            FROM ts_users
            WHERE username = :u AND enabled = 1
            LIMIT 1
        ");
        $stmt->execute([':u' => $username]);
        $user = $stmt->fetch();

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        $_SESSION['user_id'] = (int)$user['id'];

        DB::conn()->prepare("
            UPDATE ts_users SET last_login = NOW() WHERE id = ?
        ")->execute([$user['id']]);

        return true;
    }

    public static function check(): bool
    {
        return isset($_SESSION['user_id']);
    }

    public static function logout(): void
    {
        session_destroy();
    }
}
