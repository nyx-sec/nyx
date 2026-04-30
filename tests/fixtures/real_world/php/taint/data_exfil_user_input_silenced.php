<?php

function forward_message() {
    $msg = $_POST['message'];
    $ch = curl_init('https://telemetry.internal/forward');
    curl_setopt($ch, CURLOPT_POSTFIELDS, "message={$msg}");
    curl_exec($ch);
    curl_close($ch);
}
