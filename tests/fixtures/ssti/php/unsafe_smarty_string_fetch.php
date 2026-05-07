<?php
// Unsafe: `$smarty->fetch("string:" . $src)` parses the inline template
// source via the `string:` resource prefix.  Tainted $src yields SSTI.

function handler() {
    $src = $_GET['template'];
    $smarty = new \Smarty();
    return $smarty->fetch("string:" . $src);
}
