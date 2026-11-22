<?php
// The same operations on a basename, on constant paths, or via methods that
// only share a name with the builtins.
function remove_dump() {
    $dir = '/var/dumps/';
    $ok = !unlink($dir . basename($_GET['dump']));
    return $ok;
}

function constant_paths() {
    mkdir('/var/data/cache');
    touch('/var/data/cache/.stamp');
    return scandir('/var/data/cache');
}

function mode_is_not_a_path() {
    chmod('/var/data/fixed', (int) $_POST['mode']);
}

function framework_methods($request, $model, $files) {
    $upload = $request->file($_POST['field']);
    $model->touch($_POST['column']);
    $files->rename($_POST['from'], $_POST['to']);
    return $upload;
}
