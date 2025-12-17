<?php
declare(strict_types=1);

class HttpFingerprint implements ModuleInterface {

    public function getName(): string { return 'http_fingerprint'; }
    public function getVersion(): string { return '1.1.0'; }
    public function getRateLimit(): int { return 30; }

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // Try HTTPS first, then HTTP
        $result = $this->fetchUrl("https://{$domain}")
               ?? $this->fetchUrl("http://{$domain}");

        if (!$result) {
            $sig[] = ['name' => 'http_present', 'value' => 'false'];
            return ['observations' => $obs, 'signals' => $sig];
        }

        $sig[] = ['name' => 'http_present', 'value' => 'true'];

        // Status code
        $obs[] = ['key' => 'http_status', 'value' => (string)$result['status']];

        // Final URL (IMPORTANT: always the requested URL)
        $obs[] = ['key' => 'http_final_url', 'value' => $result['final_url']];

        // Headers
        foreach ($result['headers'] as $k => $v) {
            $obs[] = [
                'key'   => 'http_header_' . strtolower($k),
                'value' => $v
            ];
        }

        // Page title
        if (!empty($result['title'])) {
            $obs[] = ['key' => 'http_title', 'value' => $result['title']];
            if ($this->looksPhishyTitle($result['title'])) {
                $sig[] = ['name' => 'phishy_title', 'value' => 'true'];
            }
        }

        // Redirect chain
        if ($result['redirects'] >= 2) {
            $sig[] = ['name' => 'http_redirect_chain', 'value' => 'true'];
            $obs[] = ['key' => 'http_redirect_count', 'value' => (string)$result['redirects']];
        }

        // Login form detection
        if (!empty($result['html']) && $this->hasLoginForm($result['html'])) {
            $sig[] = ['name' => 'http_login_form', 'value' => 'true'];
        }

        // Suspicious server header
        $serverHeader = $result['headers']['Server'] ?? null;
        if ($this->isSuspiciousServer($serverHeader)) {
            $sig[] = ['name' => 'http_suspicious_server', 'value' => 'true'];
        }

        // Favicon hashing (FIXED + RELIABLE)
        $faviconHash = $this->fetchFaviconHash(
            $result['final_url'],
            $result['html']
        );

        if ($faviconHash) {
            $obs[] = ['key' => 'favicon_hash_md5', 'value' => $faviconHash];
            $sig[] = ['name' => 'favicon_present', 'value' => 'true'];
        }

        return ['observations' => $obs, 'signals' => $sig];
    }

    /* ============================
       HTTP Fetch
       ============================ */

    private function fetchUrl(string $url): ?array {
        $ch = curl_init($url);
        if (!$ch) return null;

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (ThreatScope)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HEADER         => true
        ]);

        $response = curl_exec($ch);
        if ($response === false) {
            curl_close($ch);
            return null;
        }

        $status    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerLen = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $headerRaw = substr($response, 0, $headerLen);
        $html      = substr($response, $headerLen);

        $headers = [];
        $redirects = 0;

        foreach (explode("\n", $headerRaw) as $line) {
            $line = trim($line);
            if (stripos($line, 'HTTP/') === 0) {
                $redirects++;
            } elseif (strpos($line, ':') !== false) {
                [$k, $v] = explode(':', $line, 2);
                $headers[trim($k)] = trim($v);
            }
        }

        $title = null;
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $m)) {
            $title = trim(html_entity_decode($m[1]));
        }

        return [
            'status'     => $status,
            'headers'    => $headers,
            'title'      => $title,
            'html'       => $html,
            'final_url'  => $url,          // 🔑 FIXED
            'redirects'  => max(0, $redirects - 1)
        ];
    }

    /* ============================
       Favicon Hashing (cURL-based)
       ============================ */

    private function fetchFaviconHash(string $baseUrl, string $html): ?string {
        $faviconUrls = [];

        // Parse <link rel="icon">
        if (preg_match_all('/<link[^>]+rel=["\']?(icon|shortcut icon)["\']?[^>]*>/i', $html, $matches)) {
            foreach ($matches[0] as $tag) {
                if (preg_match('/href=["\']([^"\']+)["\']/i', $tag, $m)) {
                    $faviconUrls[] = $this->resolveUrl($baseUrl, $m[1]);
                }
            }
        }

        // Fallback
        $faviconUrls[] = rtrim($baseUrl, '/') . '/favicon.ico';

        foreach (array_unique($faviconUrls) as $url) {
            $data = $this->curlGetBinary($url);
            if (!$data || strlen($data) < 100) continue;

            return md5($data);
        }

        return null;
    }

    private function curlGetBinary(string $url): ?string {
        $ch = curl_init($url);
        if (!$ch) return null;

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (ThreatScope)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HEADER         => false
        ]);

        $data = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($data === false || $code >= 400) {
            return null;
        }

        return $data;
    }

    private function resolveUrl(string $base, string $relative): string {
        if (parse_url($relative, PHP_URL_SCHEME)) {
            return $relative;
        }
        return rtrim($base, '/') . '/' . ltrim($relative, '/');
    }

    /* ============================
       Signal Helpers
       ============================ */

    private function looksPhishyTitle(string $title): bool {
        $keywords = [
            'login', 'verify', 'secure', 'account',
            'update', 'confirm', 'password', 'webmail'
        ];

        $t = strtolower($title);
        foreach ($keywords as $k) {
            if (strpos($t, $k) !== false) return true;
        }
        return false;
    }

    private function hasLoginForm(string $html): bool {
        return (bool)preg_match('/type\s*=\s*["\']password["\']/i', $html);
    }

    private function isSuspiciousServer(?string $server): bool {
        if (!$server) return false;

        $bad = [
            'openresty',
            'nginx/1.18.0',
            'apache/2.4.49'
        ];

        $s = strtolower($server);
        foreach ($bad as $b) {
            if (strpos($s, $b) !== false) return true;
        }
        return false;
    }
}
