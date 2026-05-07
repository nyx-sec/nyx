<?php
// Unsafe: Twig\Environment::createTemplate receives a tainted template
// *source* string built from $_GET; SSTI fires on the source argument.

function handler() {
    $src = $_GET['template'];
    $twig = new \Twig\Environment(new \Twig\Loader\ArrayLoader([]));
    $tpl = $twig->createTemplate($src);
    return $tpl->render(['user' => 'anon']);
}
