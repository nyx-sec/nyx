<?php
// dbFacile helpers: argument 0 is the SQL text, argument 1 the bound values.
function search_packages() {
    $query = 'SELECT name FROM packages WHERE 1=1';
    $query .= " AND name LIKE '%" . $_POST['package'] . "%'";
    return dbFetchRows($query, []);
}

function one_row() {
    return dbFetchRow('SELECT * FROM devices WHERE hostname = ' . $_GET['host']);
}

function one_cell() {
    $sql = "SELECT COUNT(*) FROM ports WHERE ifName = '" . $_GET['port'] . "'";
    return dbFetchCell($sql);
}
