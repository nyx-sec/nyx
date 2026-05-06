<?php
// Safe-template-var: Twig\Environment::render takes a *template name*
// (file lookup, not source) plus user-controlled variables.  The flat
// `Environment.createTemplate` rule only fires on the source-string
// constructor, so this stays clean even though `$_GET['name']` is passed
// at render time.

function handler() {
    $twig = new \Twig\Environment(new \Twig\Loader\FilesystemLoader('/tpl'));
    return $twig->render('greeting.html.twig', ['name' => $_GET['name']]);
}
