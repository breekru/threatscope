<?php
declare(strict_types=1);

// Load environment secrets if present
$envPath = '/home/blkfarms/env/env.php';
if (file_exists($envPath)) {
    require_once $envPath;
}

require __DIR__ . '/../app/bootstrap.php';

try {
    $scheduler = new Scheduler();
    $scheduler->run();
    echo "ThreatScope scheduler completed.\n";
} catch (Throwable $e) {
    Logger::error("Scheduler fatal: " . $e->getMessage());
    echo "ThreatScope scheduler failed: " . $e->getMessage() . "\n";
    exit(1);
}
