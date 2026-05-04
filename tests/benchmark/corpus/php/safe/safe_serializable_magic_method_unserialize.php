<?php
// `Serializable::unserialize($input)` magic-method body — the legacy
// PHP `Serializable` interface contract (deprecated since PHP 8.1).
// PHP itself invokes `\unserialize($attacker_bytes)` and then dispatches
// to this method during instance restoration; the body's `\unserialize($x)`
// call is part of the deserialization machinery and cannot be removed
// without breaking the interface.  The actionable signal lives at the
// class level (the class implements deprecated `Serializable` — fix is
// to migrate to `__serialize` / `__unserialize`), not at this call
// site.
//
// Distilled from
// joomla/administrator/components/com_finder/src/Indexer/Result.php:488
// joomla/libraries/src/Input/Cli.php:112  joomla/libraries/src/Input/Input.php:210.

class IndexerResult implements \Serializable {
    private array $data = [];

    public function unserialize($serialized): void {
        $this->data = unserialize($serialized);
    }
}

class CliInput implements \Serializable {
    public string $executable = '';
    public array $args = [];
    public array $options = [];

    public function unserialize($input): void {
        [$this->executable, $this->args, $this->options] = unserialize($input);
    }
}

class CaseFolded implements \Serializable {
    private mixed $payload = null;

    public function UnSerialize($payload) {
        $this->payload = unserialize($payload);
    }
}
