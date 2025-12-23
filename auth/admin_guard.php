<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_once __DIR__ . '/auth.php';

if (!Auth::check()) {
    header('Location: /auth/login.php');
    exit;
}

$stmt = DB::conn()->prepare("
    SELECT is_admin
    FROM ts_users
    WHERE id = ?
");
$stmt->execute([$_SESSION['user_id']]);
$isAdmin = (int)$stmt->fetchColumn();

if ($isAdmin !== 1) {
    http_response_code(403);
    echo "Access denied";
    exit;
}
