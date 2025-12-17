<?php
declare(strict_types=1);

class DB {
    private static ?PDO $pdo = null;

    public static function conn(): PDO {
        if (!self::$pdo) {
            $cfg = require __DIR__ . '/../config/database.php';

            if (empty($cfg['user']) || empty($cfg['pass'])) {
                throw new RuntimeException("DB credentials missing. Set DB_USER and DB_PASS env vars.");
            }

            self::$pdo = new PDO(
                $cfg['dsn'],
                $cfg['user'],
                $cfg['pass'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
        }
        return self::$pdo;
    }
}
