<?php
declare(strict_types=1);

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
