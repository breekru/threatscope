<?php
declare(strict_types=1);

final class JobState
{
    public static function getLastRun(string $jobName): ?string
    {
        $stmt = DB::conn()->prepare("
            SELECT last_run_at
            FROM ts_job_state
            WHERE job_name = :n
            LIMIT 1
        ");
        $stmt->execute([':n' => $jobName]);
        $val = $stmt->fetchColumn();
        return $val ? (string)$val : null;
    }

    public static function touch(string $jobName): void
    {
        $stmt = DB::conn()->prepare("
INSERT INTO ts_job_state (job_name, last_run_at, updated_at)
VALUES (:n, UTC_TIMESTAMP(), UTC_TIMESTAMP())
ON DUPLICATE KEY UPDATE
    last_run_at = UTC_TIMESTAMP(),
    updated_at  = UTC_TIMESTAMP()

        ");
        $stmt->execute([':n' => $jobName]);
    }
}
