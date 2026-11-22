<?php
// Request data from the request object still reaches the filesystem.
function cleanup_from_request() {
    $request = Request::createFromGlobals();
    $name = $request->server->get('PATH_INFO');
    unlink('/var/tmp/' . $name);
}
