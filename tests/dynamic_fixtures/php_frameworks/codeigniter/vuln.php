<?php
// CodeIgniter-style route, vulnerable.

namespace App\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\Router\RouteCollection;

function nyx_register_routes(RouteCollection $routes): void
{
    $routes->get('run/(:any)', 'App\\Controllers\\UserController::run');
}

class UserController extends Controller
{
    public function run(string $payload): string
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . $payload;
        $out = shell_exec($cmd) ?? '';
        echo $out;
        return $out;
    }
}
