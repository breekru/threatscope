<?php
declare(strict_types=1);

/*
 |--------------------------------------------------------------------------
 | ThreatScope Application Configuration
 |--------------------------------------------------------------------------
 | Single source of truth for runtime behavior.
 | Loaded once via bootstrap.php and injected globally as $appConfig.
 |
 | RULES:
 | - Modules read config only
 | - Scheduler owns persistence
 | - No side effects here
 |--------------------------------------------------------------------------
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Application Metadata
    |--------------------------------------------------------------------------
    */
    'app' => [
        'name'        => 'ThreatScope',
        'environment' => 'production', // production | staging | dev
        'timezone'    => 'UTC',
    ],

    /*
    |--------------------------------------------------------------------------
    | Database Configuration
    |--------------------------------------------------------------------------
    */
    'db' => [
        'host'     => 'localhost',
        'database' => 'threatscope',
        'username' => 'threatscope_user',
        'password' => 'REPLACE_ME',
        'charset'  => 'utf8mb4',
        'options'  => [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */
    'logging' => [
        'enabled' => true,
        'path'    => __DIR__ . '/../storage/logs/threatscope.log',
        'level'   => 'info', // debug | info | warning | error
    ],

    /*
    |--------------------------------------------------------------------------
    | Module Registry
    |--------------------------------------------------------------------------
    | Controls which intelligence modules run.
    | Modules DO NOT write to DB.
    |--------------------------------------------------------------------------
    */
    'modules' => [

        'DnsBasic' => [
            'enabled' => true,
        ],

        'MxCheck' => [
            'enabled' => true,
        ],

        'WhoisBasic' => [
            'enabled' => true,
            'recent_days_threshold' => 30,
        ],

        'TlsIntel' => [
            'enabled' => true,
            'min_key_size' => 2048,
        ],

        'HttpFingerprint' => [
            'enabled' => true,
            'timeout_seconds' => 10,
            'follow_redirects' => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Risk Scoring
    |--------------------------------------------------------------------------
    | Signals → weights → normalized risk_score (0–100)
    |--------------------------------------------------------------------------
    */
    'scoring' => [

        'max_score' => 100,

        'weights' => [

            // WHOIS
            'whois_recent_registration' => 20,
            'whois_privacy_enabled'     => 10,

            // DNS / MX
            'mx_missing'                => 10,

            // TLS
            'tls_self_signed'           => 20,
            'tls_hostname_mismatch'     => 20,
            'tls_weak_key'              => 15,

            // HTTP / Content
            'http_login_brand_impersonation' => 30,
            'favicon_hash_reused'            => 25,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alerts & Notifications  (BUILD STEP 6)
    |--------------------------------------------------------------------------
    */
    'alerts' => [

        /*
         | Master switch
         */
        'enabled' => true,

        /*
         | Risk thresholds (must align with scoring scale)
         */
        'high_threshold'     => 1,
        'critical_threshold' => 90,

        /*
         | Signals that generate alerts ONLY when first_seen_at occurs.
         | Keep tight to avoid SOC noise.
         */
        'high_risk_signals' => [
            'whois_recent_registration',
            'tls_self_signed',
            'tls_hostname_mismatch',
            'favicon_hash_reused',
            'http_login_brand_impersonation',
        ],

        /*
         | Email delivery (shared-hosting safe)
         */
        'email' => [
            'enabled' => true,

            // One or more recipients
            'to' => [
                'soc@yourcompany.com',
            ],

            'from' => 'threatscope@yourcompany.com',
            'subject_prefix' => '[ThreatScope]',
        ],
    ],

];
