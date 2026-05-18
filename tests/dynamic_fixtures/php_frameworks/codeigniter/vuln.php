<?php
// Phase 16 — CodeIgniter-style route, vulnerable.
// `$routes->get('run', 'UserController::run')` references the
// controller method whose body shells out without sanitisation.

use CodeIgniter\Router\RouteCollection;

$routes->get('run', 'UserController::run');

class UserController extends BaseController
{
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . $payload;
        $out = shell_exec($cmd);
        echo $out;
        return $out;
    }
}
