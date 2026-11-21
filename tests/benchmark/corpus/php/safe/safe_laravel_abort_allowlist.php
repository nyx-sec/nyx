<?php
namespace App\Http\Controllers;

class ToolController
{
    public function run($request)
    {
        $allowed = ['ls', 'pwd'];
        $cmd = $_GET['cmd'];
        if (!in_array($cmd, $allowed, true)) {
            \abort(403);
        }
        system($cmd);
    }
}
