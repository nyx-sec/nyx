<?php
// Phase 16 — Laravel-style route, vulnerable.
// `Route::get('/run', 'UserController@run')` references the
// controller method whose body shells out without sanitisation.

use Illuminate\Support\Facades\Route;

Route::get('/run', 'UserController@run');

class UserController
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
