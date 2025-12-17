<?php
declare(strict_types=1);

class HttpFingerprint implements ModuleInterface {
    public function getName(): string { return 'http_fingerprint'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRateLimit(): int { return 30; } // HTTP is lighter than TLS

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // Try HTTPS first, then HTTP
        $result = $this->fetchUrl("https://{$domain}") ??
                  $this->fetchUrl("http://{$domain}");

        if (!$result) {
            $sig[] = ['name' => 'http_present', 'value' => 'false'];
            return ['observations' => $obs, 'signals' => $sig];
        }

        $sig[] = ['name' => 'http_present', 'value' => 'true'];

        // Status
        $obs[] = ['key' => 'http_status', 'value' => (string)$result['status']];

        // Final URL (after redirects)
        if (!empty($result['final_url'])) {
            $obs[] = ['key' => 'http_final_url', 'value' => $result['final_url']];
        }

        // Headers
        foreach ($result['headers'] as $k => $v) {
            $obs[] = ['key' => 'http_header_' . strtolower($k), 'value' => $v];
        }

        // Page title
        if (!empty($result['title'])) {
            $obs[] = ['key' => 'http_title', 'value' => $result['title']];

            if ($this->looksPhishyTitle($result['title'])) {
                $sig[] = ['name' => 'phishy_title', 'value' => 'true'];
            }
        }

        // Redirect chain detection
        if (($result['redirects'] ?? 0) >= 2) {
            $sig[] = ['name' => 'http_redirect_chain', 'value' => 'true'];
            $obs[] = ['key' => 'http_redirect_count', 'value' => (string)$result['redirects']];
        }

        // Login form detection
        if (!empty($result['html']) && $this->hasLoginForm($result['html'])) {
            $sig[] = ['name' => 'http_login_form', 'value' => 'true'];
        }

        // Suspicious server header
        $serverHeader = $result['headers']['Server'] ?? null;
        if ($this->suspiciousServer($serverHeader)) {
            $sig[] = ['name' => 'http_suspicious_server', 'value' => 'true'];
        }

        // Favicon hash
        $faviconHash = $this->fetchFaviconHash($result['final_url'] ?? '');
        if ($faviconHash) {
            $obs[] = ['key' => 'favicon_hash_md5', 'value' => $faviconHash];
            $sig[] = ['name' => 'favicon_present', 'value' => 'true'];
        }

        return ['observations' => $obs, 'signals' => $sig];
    }

    /* ================= Helpers ================= */

    private function fetchUrl(string $url): ?array {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'follow_location' => 1,
                'max_redirects' => 5,
                'header' => "User-Agent: ThreatScope/1.0\r\n"
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]
        ]);

        $headers = [];
        $content = @file_get_contents($url, false, $ctx);
        if ($content === false || empty($http_response_header)) {
            return null;
        }

        // Status line
        $statusLine = $http_response_header[0] ?? '';
        preg_match('#HTTP/\d\.\d\s+(\d+)#', $statusLine, $m);
        $status = $m[1] ?? '0';

        // Parse headers
        foreach ($http_response_header as $h) {
            if (strpos($h, ':') !== false) {
                [$k, $v] = explode(':', $h, 2);
                $headers[trim($k)] = trim($v);
            }
        }

        // Title extraction
        $title = null;
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $content, $m)) {
            $title = trim(html_entity_decode($m[1]));
        }

        return [
            'status' => $status,
            'headers' => $headers,
            'title' => $title,
            'html' => $content,
            'final_url' => $this->extractFinalUrl($http_response_header),
            'redirects' => count(array_filter($http_response_header, fn($h) => stripos($h, 'Location:') === 0))
        ];
        
    }

    private function extractFinalUrl(array $responseHeaders): ?string {
        foreach (array_reverse($responseHeaders) as $h) {
            if (stripos($h, 'Location:') === 0) {
                return trim(substr($h, 9));
            }
        }
        return null;
    }

    private function hasLoginForm(string $html): bool {
        return (bool)preg_match('/type\s*=\s*["\']password["\']/i', $html);
    }
    
    private function suspiciousServer(?string $server): bool {
        if (!$server) return false;
    
        $bad = [
            'nginx/1.18.0',
            'openresty',
            'cloudflare',
            'apache/2.4.49'
        ];
    
        $s = strtolower($server);
        foreach ($bad as $b) {
            if (strpos($s, $b) !== false) return true;
        }
        return false;
    }

    private function fetchFaviconHash(string $baseUrl): ?string {
        if (!$baseUrl) return null;

        $faviconUrl = rtrim($baseUrl, '/') . '/favicon.ico';
        $ctx = stream_context_create([
            'http' => ['timeout' => 10],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
        ]);

        $data = @file_get_contents($faviconUrl, false, $ctx);
        if (!$data) return null;

        return md5($data);
    }

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
}
