<?php
// Phase 16 — Symfony-style route via `#[Route]` attribute,
// vulnerable.

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController
{
    #[Route('/run', methods: ['GET'])]
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "echo hello " . $payload;
        $out = shell_exec($cmd);
        echo $out;
        return new Response($out);
    }
}
