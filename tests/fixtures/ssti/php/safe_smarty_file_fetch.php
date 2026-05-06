<?php
// Safe: `$smarty->fetch('page.tpl')` uses the bare-file resource (no
// `string:` prefix), so the gated Smarty SSTI rule does not activate.
// Variables assigned via assign() carry user input but flow into a file-
// loaded template, not into a source string.

function handler() {
    $smarty = new \Smarty();
    $smarty->assign('name', $_GET['name']);
    return $smarty->fetch('page.tpl');
}
