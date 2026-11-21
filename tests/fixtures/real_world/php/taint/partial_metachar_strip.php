<?php
$host = $_GET['host'];
$host = str_replace(";", "", $host);
system("ping -c 1 " . $host);
