<?php
// Safe: Twig\Environment::createTemplate receives a constant template
// source.  Variables passed at render time carry user input but do not
// activate SSTI.

function handler() {
    $twig = new \Twig\Environment(new \Twig\Loader\ArrayLoader([]));
    $tpl = $twig->createTemplate('Hello, {{ name }}');
    return $tpl->render(['name' => $_GET['name']]);
}
