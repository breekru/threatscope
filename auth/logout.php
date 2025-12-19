<?php
require_once __DIR__ . '/app/bootstrap.php';
require_once __DIR__ . '/auth.php';

Auth::logout();
header('Location: /auth/login.php');
exit;
