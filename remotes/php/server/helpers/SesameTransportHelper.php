<?php

#[Helper]
class SesameTransportHelper {
    private const SNAPSHOT_VARIABLE = 'YON_APPLICATION_JSON';
    private const SECURE_SCHEME = 'https';
    private const PLAIN_SCHEME = 'http';
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];
    private const ROOT_PATHS = ['', '/'];
    private const SCHEME = 'scheme';
    private const HOST = 'host';
    private const PORT = 'port';
    private const PATH = 'path';
    private const DEADLINE = 'deadline';
    private const BODY = 'body';
    private const PORT_SEPARATOR = ':';
    private const ORIGIN_PARTS = [self::SCHEME, self::HOST, self::PORT, self::PATH];
    private const UNSAFE_ORIGIN_CHARACTERS = '?#';
    private const SECURE_PROXY_VARIABLES = ['HTTPS_PROXY', 'https_proxy'];
    private const PLAIN_PROXY_VARIABLES = ['http_proxy'];
    private const PROXY_SCHEME = 'tcp://';
    private const JSON_TYPE = 'application/json';
    private const STATUS_PATTERN = '#^HTTP/\S+\s+(\d{3})#';
    private const FIRST_REDIRECT_STATUS = 300;
    private const FIRST_OTHER_STATUS = 400;
    private const READ_CHUNK_BYTES = 65536;
    private const MILLISECONDS_PER_SECOND = 1000;
    private const ORIGIN_RULE = 'sesame.origin must be an https origin without a path, or http on a loopback address';
    private const NETWORK_RULE = 'SESAME could not be reached';
    private const REDIRECT_RULE = 'SESAME answered with a redirect, which this transport never follows';
    private const SIZE_RULE = "SESAME's answer is larger than the response limit";
    private const DEADLINE_RULE = 'SESAME did not answer before the deadline';

    public function exchange(array $request, mixed $execution): array {
        $origin = $this->origin();
        $stream = $this->opened($this->address($origin, $request), $this->context($origin, $request));
        try {
            $status = $this->status(stream_get_meta_data($stream)['wrapper_data'] ?? []);
            $content = $this->read($stream, $request['maxResponseBytes'], $request[self::DEADLINE]);
        } finally {
            fclose($stream);
        }
        return ['status' => $status, self::BODY => json_decode($content, true)];
    }

    private function origin(): array {
        $snapshot = json_decode(getenv(self::SNAPSHOT_VARIABLE) ?: '{}', true);
        $origin = $snapshot['yon']['sesame']['origin'] ?? '';
        $parts = is_string($origin) ? parse_url($origin) : false;
        if (!is_array($parts) || !$this->usable($origin, $parts)) {
            throw new RuntimeException(self::ORIGIN_RULE);
        }
        return $parts;
    }

    private function usable(string $origin, array $parts): bool {
        $checks = [
            $this->allowedScheme($parts),
            strpbrk($origin, self::UNSAFE_ORIGIN_CHARACTERS) === false,
            array_diff(array_keys($parts), self::ORIGIN_PARTS) === [],
            in_array($parts[self::PATH] ?? '', self::ROOT_PATHS, true),
        ];
        return !in_array(false, $checks, true);
    }

    private function allowedScheme(array $parts): bool {
        $scheme = $parts[self::SCHEME] ?? '';
        $secure = $scheme === self::SECURE_SCHEME && ($parts[self::HOST] ?? '') !== '';
        $local = $scheme === self::PLAIN_SCHEME && in_array($parts[self::HOST] ?? '', self::LOOPBACK_HOSTS, true);
        return $secure || $local;
    }

    private function address(array $origin, array $request): string {
        $port = isset($origin[self::PORT]) ? self::PORT_SEPARATOR . $origin[self::PORT] : '';
        $query = $this->query($request['query']);
        return $origin[self::SCHEME] . '://' . $origin[self::HOST] . $port . $request[self::PATH] . ($query === '' ? '' : '?' . $query);
    }

    private function query(array $values): string {
        $plain = array_map(fn (mixed $value): string => is_bool($value) ? json_encode($value) : (string) $value, $values);
        return http_build_query($plain, '', '&', PHP_QUERY_RFC3986);
    }

    private function context(array $origin, array $request): mixed {
        $options = [
            'method' => $request['method'],
            'header' => $this->headerLines($request),
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => $this->remainingSeconds($request[self::DEADLINE]),
        ];
        return stream_context_create(['http' => $this->withBody($this->withProxy($options, $origin), $request)]);
    }

    private function headerLines(array $request): array {
        $lines = ['Accept: ' . self::JSON_TYPE, 'Content-Type: ' . self::JSON_TYPE];
        foreach ($request['headers'] as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        return $lines;
    }

    private function withProxy(array $options, array $origin): array {
        $secure = $origin[self::SCHEME] === self::SECURE_SCHEME;
        $proxy = $this->proxy($secure ? self::SECURE_PROXY_VARIABLES : self::PLAIN_PROXY_VARIABLES);
        if ($proxy === '') {
            return $options;
        }
        return $options + ['proxy' => $proxy, 'request_fulluri' => !$secure];
    }

    private function proxy(array $variables): string {
        foreach ($variables as $variable) {
            $parts = parse_url((string) getenv($variable));
            if (is_array($parts) && isset($parts[self::HOST], $parts[self::PORT])) {
                return self::PROXY_SCHEME . $parts[self::HOST] . self::PORT_SEPARATOR . $parts[self::PORT];
            }
        }
        return '';
    }

    private function withBody(array $options, array $request): array {
        if (!array_key_exists(self::BODY, $request)) {
            return $options;
        }
        return $options + ['content' => json_encode($request[self::BODY], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)];
    }

    private function opened(string $address, mixed $context): mixed {
        set_error_handler(static fn (): bool => true);
        try {
            $stream = fopen($address, 'rb', false, $context);
        } finally {
            restore_error_handler();
        }
        if ($stream === false) {
            throw new RuntimeException(self::NETWORK_RULE);
        }
        return $stream;
    }

    private function status(array $headers): int {
        $matched = preg_match(self::STATUS_PATTERN, (string) ($headers[0] ?? ''), $parts) === 1;
        $status = $matched ? (int) $parts[1] : 0;
        if (!$matched || ($status >= self::FIRST_REDIRECT_STATUS && $status < self::FIRST_OTHER_STATUS)) {
            throw new RuntimeException($matched ? self::REDIRECT_RULE : self::NETWORK_RULE);
        }
        return $status;
    }

    private function read(mixed $stream, int $limit, int $deadline): string {
        $content = '';
        while (!feof($stream)) {
            stream_set_timeout($stream, max(1, (int) ceil($this->remainingSeconds($deadline))));
            $content .= (string) fread($stream, self::READ_CHUNK_BYTES);
            $this->requireWithin(strlen($content), $limit, $deadline);
        }
        return $content;
    }

    private function requireWithin(int $size, int $limit, int $deadline): void {
        if ($size > $limit) {
            throw new RuntimeException(self::SIZE_RULE);
        }
        if ($this->remainingSeconds($deadline) <= 0) {
            throw new RuntimeException(self::DEADLINE_RULE);
        }
    }

    private function remainingSeconds(int $deadline): float {
        return ($deadline - floor(microtime(true) * self::MILLISECONDS_PER_SECOND)) / self::MILLISECONDS_PER_SECOND;
    }
}
