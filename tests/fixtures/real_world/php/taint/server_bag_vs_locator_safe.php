<?php
// `Server::get(Foo::class)` is a service locator lookup, not request data.
function cleanup_from_locator() {
    $tempManager = \OCP\Server::get(ITempManager::class);
    $dir = $tempManager->getTemporaryFolder();
    unlink($dir . '/marker');
    mkdir($dir . '/work');
}
