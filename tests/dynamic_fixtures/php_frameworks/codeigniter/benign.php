<?php
// Phase 16 — CodeIgniter-style route, benign sanitised payload.

namespace CodeIgniter\Router {
    class RouteCollection
    {
    }
}

namespace {
use CodeIgniter\Router\RouteCollection;

class BaseController
{
}

class NyxRoutes extends RouteCollection
{
    public function get(string $path, string $callable)
    {
        $GLOBALS['__nyx_route'] = function (string $payload) use ($callable) {
            [$class, $method] = explode('::', $callable, 2);
            $controller = new $class();
            return $controller->$method($payload);
        };
        return $this;
    }
}

$routes = new NyxRoutes();
$routes->get('run', 'UserController::run');

class UserController extends BaseController
{
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "true " . escapeshellarg($payload);
        $out = shell_exec($cmd);
        echo $out;
        return $out;
    }
}
}
