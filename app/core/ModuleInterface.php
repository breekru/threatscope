<?php
declare(strict_types=1);

interface ModuleInterface {
    public function getName(): string;
    public function getVersion(): string;
    public function getRateLimit(): int;
    public function run(string $domain): array;
}
