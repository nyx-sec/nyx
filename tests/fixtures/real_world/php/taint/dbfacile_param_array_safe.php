<?php
// The user value travels in the parameter array, which is the safe channel.
function search_packages() {
    $query = 'SELECT name FROM packages WHERE name LIKE ?';
    $param = [];
    $param[] = '%' . $_POST['package'] . '%';
    return dbFetchRows($query, $param);
}

function one_row() {
    return dbFetchRow('SELECT * FROM devices WHERE hostname = ?', [$_GET['host']]);
}

function paged($page) {
    $start = ((int) $_POST['page'] - 1) * 20;
    $limit = ($_POST['size'] - 1) * 2;
    return dbFetchRows("SELECT * FROM ports LIMIT $start,$limit", []);
}
