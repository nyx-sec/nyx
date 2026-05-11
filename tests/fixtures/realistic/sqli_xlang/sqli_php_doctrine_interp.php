<?php
// Phase 15 — PHP Doctrine `createQuery` interpolation SQLi positive.
// `EntityManager.createQuery` (suffix `createQuery`) is a flat
// SQL_QUERY sink in `labels/php.rs`; the double-quoted string
// interpolates `$_GET['name']` directly into the DQL string with no
// parameterisation.

$em = $container->get('doctrine.orm.entity_manager');
$name = $_GET['name'];
$query = $em->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.name = '$name'");
$rows = $query->getResult();
print_r($rows);
