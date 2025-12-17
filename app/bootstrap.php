<?php
declare(strict_types=1);

date_default_timezone_set('UTC');

spl_autoload_register(function ($class) {
    $paths = [
        __DIR__ . '/core/' . $class . '.php',
    ];
    foreach ($paths as $p) {
        if (file_exists($p)) { require_once $p; return; }
    }
});

// Load config (simple arrays)
$appConfig = require __DIR__ . '/config/app.php';

// Basic sanity checks
if (!is_dir(__DIR__ . '/../storage/logs')) {
    @mkdir(__DIR__ . '/../storage/logs', 0750, true);
}
if (!is_dir(__DIR__ . '/../storage/evidence')) {
    @mkdir(__DIR__ . '/../storage/evidence', 0750, true);
}
