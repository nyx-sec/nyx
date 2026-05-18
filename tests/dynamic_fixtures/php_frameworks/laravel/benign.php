<?php
// Phase 16 — Laravel-style route, benign sanitised payload.

use Illuminate\Support\Facades\Route;

Route::get('/run', 'UserController@run');

class UserController
{
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . escapeshellarg($payload);
        $out = shell_exec($cmd);
        echo $out;
        return $out;
    }
}
