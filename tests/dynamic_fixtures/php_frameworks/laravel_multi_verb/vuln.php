<?php
// Laravel-style multi-verb route fixture. The vulnerable sink is gated
// to POST so verifier runs that exercise only the representative GET
// method miss the command injection.

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
            $cmd = "true " . $payload;
            $out = shell_exec($cmd);
            echo $out;
            return $out;
        }
    }
}
