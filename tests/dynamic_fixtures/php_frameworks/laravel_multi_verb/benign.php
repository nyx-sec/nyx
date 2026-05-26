<?php
// Same route shape as vuln.php, but quotes the payload before invoking
// the shell so the command-injection marker remains inert.

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
        $cmd = "true " . escapeshellarg($payload);
        $out = shell_exec($cmd) ?? '';
        echo $out;
        return $out;
    }
}
