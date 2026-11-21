<?php
class Loader {
    private $path;

    public function load() {
        $path = "/tmp/report.txt";
        $this->path = $_GET["path"];
        return file_get_contents($path);
    }
}
