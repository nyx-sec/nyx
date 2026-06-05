<?php
// Symfony-style route via RouteCollection and HttpKernel, vulnerable.

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Route as SymfonyRoute;
use Symfony\Component\Routing\RouteCollection;

function nyx_register_routes(RouteCollection $routes): void
{
    $routes->add('nyx_run', new SymfonyRoute(
        '/run/{payload}',
        ['_controller' => [new UserController(), 'run']],
        [],
        [],
        '',
        [],
        ['GET']
    ));
}

class UserController
{
    #[Route('/run/{payload}', methods: ['GET'])]
    public function run(string $payload): Response
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . $payload;
        $out = shell_exec($cmd) ?? '';
        echo $out;
        return new Response($out);
    }
}
