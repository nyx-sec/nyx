<?php
// Phase 16 — Symfony-style route via `#[Route]` attribute,
// benign sanitised payload.

namespace Symfony\Component\HttpFoundation {
    class Response
    {
        public function __construct(private string $content)
        {
        }

        public function __toString(): string
        {
            return $this->content;
        }
    }
}

namespace Symfony\Component\Routing\Annotation {
    #[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
    class Route
    {
        public function __construct(...$args)
        {
        }
    }
}

namespace App\Controller {

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController
{
    #[Route('/run', methods: ['GET'])]
    public function run($payload)
    {
        echo "__NYX_SINK_HIT__\n";
        $cmd = "true " . escapeshellarg($payload);
        $out = shell_exec($cmd);
        echo $out;
        return new Response($out);
    }
}

$GLOBALS['__nyx_controller'] = new UserController();
}
