<?php
// Superglobals read directly by echo / print / <?= reach the output.
function show_plain() {
    echo $_GET['a'];
}

function show_suppressed() {
    echo @$_REQUEST['x'];
}

function show_concat() {
    echo 'Hello ' . $_GET['b'];
}

function show_print() {
    print $_GET['c'];
}

function show_list() {
    echo $_GET['f'], ' done';
}

function show_short_tag() {
    ?>
    <b><?= $_GET['q'] ?></b>
    <?php
}
