<?php
$city = $_GET['city'];
echo file_get_contents('https://api.example.com/weather?city=' . $city);
$id = $_GET['id'];
echo file_get_contents("https://api.example.com/items/{$id}");
