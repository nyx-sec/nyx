<?php
// Phase 16 — CodeIgniter-style route, benign sanitised payload.

use CodeIgniter\Router\RouteCollection;

$routes->get('run', 'UserController::run');

class UserController extends BaseController
{
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . escapeshellarg($payload);
        $out = shell_exec($cmd);
        echo $out;
        return $out;
    }
}
