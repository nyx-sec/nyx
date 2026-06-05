<?php
// Phase 21 (Track M.3) — Laravel middleware vuln fixture.
//
// `Audit::handle($request, $next)` splices `$request->body` into a
// shell command via `shell_exec` — classic Laravel middleware cmdi.

// use Illuminate\\Http\\Request;
// function handle($request, Closure $next)

class Audit {
    public function handle($request, $next) {
        $body = is_object($request) && isset($request->body) ? (string)$request->body : (string)$request;
        // SINK: tainted body concatenated into shell command.
        shell_exec("echo " . $body);
        return $next($request);
    }
}
