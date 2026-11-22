<?php
// An integer cast stored into one field must not clear the taint another
// field of the same object already carries.
function object_field() {
    $o = new stdClass;
    $o->path = $_GET['p'];
    $o->count = (int) $_GET['n'];
    unlink($o->path);
}

class Remover {
    public $target;

    public function run() {
        $this->target = $_GET['p'];
        $this->limit = (int) $_GET['n'];
        unlink($this->target);
    }
}
