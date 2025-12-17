<?php
declare(strict_types=1);

class Logger {
    public static function info(string $msg): void {
        self::write('INFO', $msg);
    }
    public static function error(string $msg): void {
        self::write('ERROR', $msg);
    }
    private static function write(string $level, string $msg): void {
        $line = sprintf("[%s] [%s] %s\n", date('c'), $level, $msg);
        $path = __DIR__ . '/../../storage/logs/threatscope.log';
        file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    }
}
