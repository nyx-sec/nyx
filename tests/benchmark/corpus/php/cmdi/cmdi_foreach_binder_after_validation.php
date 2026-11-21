<?php
$value = $_GET['page'];
if (!is_numeric($value)) {
    die("bad");
}
echo "page " . intval($value);
foreach ($_POST['names'] as $value) {
    system("echo " . $value);
}
