<?php
// Safe: concatenation in the call argument.
function weather() {
    $city = $_GET['city'];
    echo file_get_contents('https://api.example.com/weather?city=' . $city);
}

// Safe: double-quoted interpolation with a fixed head.
function item() {
    $id = $_GET['id'];
    echo file_get_contents("https://api.example.com/items/{$id}");
}

// Safe: the same through a variable.
function itemVar() {
    $id = $_GET['id'];
    $url = "https://api.example.com/items/{$id}";
    echo file_get_contents($url);
}

// Vulnerable: the request parameter is the whole URL.
function raw() {
    $url = $_GET['url'];
    echo file_get_contents($url);
}
