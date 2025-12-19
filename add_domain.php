<?php
require_once __DIR__ . '/auth/guard.php';
require_once __DIR__ . '/partials/header.php';
//require __DIR__ . '/app/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$domain = strtolower(trim($_POST['domain'] ?? ''));
if (!$domain || !preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $domain)) {
    die('Invalid domain');
}

$pdo = DB::conn();

$stmt = $pdo->prepare("
INSERT INTO ts_domains (domain, status, first_seen, last_seen)
VALUES (:d, 'new', NOW(), NOW())
ON DUPLICATE KEY UPDATE last_seen = NOW()
");
$stmt->execute([':d' => $domain]);

header('Location: index.php');
