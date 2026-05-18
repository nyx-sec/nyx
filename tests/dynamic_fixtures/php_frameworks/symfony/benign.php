<?php
// Phase 16 — Symfony-style route via `#[Route]` attribute,
// benign sanitised payload.

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController
{
    #[Route('/run', methods: ['GET'])]
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . escapeshellarg($payload);
        $out = shell_exec($cmd);
        echo $out;
        return new Response($out);
    }
}
