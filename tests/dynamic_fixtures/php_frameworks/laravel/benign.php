<?php
// Laravel-style route, benign sanitised payload.

namespace App\Http\Controllers;

use Illuminate\Routing\Router;

function nyx_register_routes(Router $router): void
{
    $router->get('/run/{payload}', [UserController::class, 'run']);
}

class UserController
{
    public function run(string $payload): string
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "true " . escapeshellarg($payload);
        $out = shell_exec($cmd) ?? '';
        echo $out;
        return $out;
    }
}
