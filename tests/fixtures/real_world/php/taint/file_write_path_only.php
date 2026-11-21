<?php
function log_feedback() {
    file_put_contents('/var/log/feedback.log', $_POST['text'] . "\n", FILE_APPEND);
    $fh = fopen('/var/log/app.log', 'a');
    fwrite($fh, $_POST['msg']);
    fclose($fh);
}

function save_upload() {
    file_put_contents('/var/www/uploads/' . $_GET['name'], 'data');
    move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/' . $_POST['dest']);
    copy($_GET['from'], '/tmp/copy.txt');
}

function store_upload() {
    move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/avatar.png');
}
