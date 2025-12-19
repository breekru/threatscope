<?php
declare(strict_types=1);

// Load environment secrets if present
$envPath = '/home/blkfarms/env/env.php';
if (file_exists($envPath)) {
    require_once $envPath;
}

require __DIR__ . '/../app/bootstrap.php';

$command = $argv[1] ?? 'run';

try {
    switch ($command) {

        // Default behavior (unchanged)
        case 'run':
            $scheduler = new Scheduler();
            $scheduler->run();
            echo "ThreatScope scheduler completed.\n";
            break;

        // NEW: Evaluate alerts only
        case 'evaluate-alerts':
            global $appConfig;
            $evaluator = new AlertEvaluator($appConfig);
            $evaluator->evaluate();
            echo "ThreatScope alert evaluation completed.\n";
            break;

        // NEW: Send pending alerts
        case 'send-alerts':
            global $appConfig;
            $notifier = new EmailNotifier($appConfig);
            $notifier->sendPending();
            echo "ThreatScope alert dispatch completed.\n";
            break;

        default:
            echo "Unknown command: {$command}\n";
            echo "Usage:\n";
            echo "  php scheduler/run.php\n";
            echo "  php scheduler/run.php run\n";
            echo "  php scheduler/run.php evaluate-alerts\n";
            echo "  php scheduler/run.php send-alerts\n";
            exit(1);
    }

} catch (Throwable $e) {
    Logger::error("Scheduler fatal ({$command}): " . $e->getMessage());
    echo "ThreatScope failed ({$command}): " . $e->getMessage() . "\n";
    exit(1);
}
