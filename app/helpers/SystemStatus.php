<?php
declare(strict_types=1);

final class SystemStatus
{
    public static function lastSchedulerRun(): ?string
    {
        $stmt = DB::conn()->prepare("
            SELECT last_run_at
            FROM ts_job_state
            WHERE job_name = 'scheduler_run'
            LIMIT 1
        ");
        $stmt->execute();
        $val = $stmt->fetchColumn();
        return $val ?: null;
    }
}
