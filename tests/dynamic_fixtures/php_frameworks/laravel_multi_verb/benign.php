<?php
// Same route shape as vuln.php, but quotes the payload before invoking
// the shell so the command-injection marker remains inert.

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function match(array $methods, string $path, array $callable)
        {
            \NyxLaravelMultiVerb\register_route($methods, $callable);
            return new class {
                public function middleware($value)
                {
                    return $this;
                }
            };
        }
    }
}

namespace NyxLaravelMultiVerb {
    use Illuminate\Support\Facades\Route;

    function register_route(array $methods, array $callable): void
    {
        $GLOBALS['__nyx_route'] = function (string $payload) use ($methods, $callable) {
            $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
            if (!in_array($requestMethod, $methods, true)) {
                return null;
            }
            [$class, $method] = $callable;
            $controller = new $class();
            return $controller->$method($payload);
        };
    }

    Route::match(['GET', 'POST'], '/run', [UserController::class, 'run']);

    class UserController
    {
        public function run(string $payload)
        {
            if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
                echo "__NYX_METHOD_SKIP__\n";
                return null;
            }
            echo "__NYX_SINK_HIT__\n";
            $cmd = "true " . escapeshellarg($payload);
            $out = shell_exec($cmd);
            echo $out;
            return $out;
        }
    }
}
