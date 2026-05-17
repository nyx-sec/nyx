<?php
// Phase 04 (Track J.2) — PHP Twig SSTI vuln fixture.
//
// The body is handed straight to Twig\Environment::createTemplate so
// an attacker who controls the body reaches Twig's expression
// evaluator and can render arbitrary expressions.
use Twig\Environment;
use Twig\Loader\ArrayLoader;

function run(string $body): string {
    $twig = new Environment(new ArrayLoader([]));
    $template = $twig->createTemplate($body);
    return $template->render([]);
}
