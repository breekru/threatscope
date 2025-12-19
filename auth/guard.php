<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/auth.php';

if (!Auth::check()) {
    header('Location: /auth/login.php');
    exit;
}
