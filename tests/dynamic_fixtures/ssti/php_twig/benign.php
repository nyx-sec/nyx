<?php
// Phase 04 (Track J.2) — PHP Twig benign control fixture.
//
// Renders a fixed template that interpolates the user value as a
// variable; the body never reaches the template compiler.
use Twig\Environment;
use Twig\Loader\ArrayLoader;

function run(string $body): string {
    $twig = new Environment(new ArrayLoader([
        'page' => '{{ safe_body }}',
    ]));
    return $twig->render('page', ['safe_body' => $body]);
}
