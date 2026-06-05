<?php
// Phase 21 — Laravel middleware benign control.
// use Illuminate\\Http\\Request;

class Audit {
    public function handle($request, $next) {
        $body = is_object($request) && isset($request->body) ? (string)$request->body : (string)$request;
        shell_exec("echo " . escapeshellarg($body));
        return $next($request);
    }
}
