<?php
// Laravel-style multi-verb route fixture. The vulnerable sink is gated
// to POST so verifier runs that exercise only GET miss the command injection.

namespace App\Http\Controllers;

use Illuminate\Routing\Router;

function nyx_register_routes(Router $router): void
{
    $router->match(['GET', 'POST'], '/run/{payload}', [UserController::class, 'run']);
}

class UserController
{
    public function run(string $payload): ?string
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            echo "__NYX_METHOD_SKIP__\n";
            return null;
        }
        echo "__NYX_SINK_HIT__\n";
        $cmd = "true " . $payload;
        $out = shell_exec($cmd) ?? '';
        echo $out;
        return $out;
    }
}
