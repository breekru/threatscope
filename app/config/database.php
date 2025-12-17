<?php
return [
    'dsn'  => 'mysql:host=localhost;dbname=threatscope;charset=utf8mb4',
    'user' => getenv('DB_USER'),
    'pass' => getenv('DB_PASS')
];
