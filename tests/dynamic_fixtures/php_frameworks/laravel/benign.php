<?php
// Phase 16 — Laravel-style route, benign sanitised payload.

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function get(string $path, string $callable)
        {
            $GLOBALS['__nyx_route'] = function (string $payload) use ($callable) {
                [$class, $method] = preg_split('/@|::/', $callable);
                $controller = new $class();
                return $controller->$method($payload);
            };
            return new class {
                public function middleware($value)
                {
                    return $this;
                }
            };
        }
    }
}

namespace {
use Illuminate\Support\Facades\Route;

Route::get('/run', 'UserController@run');

class UserController
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
