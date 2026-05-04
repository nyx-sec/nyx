<?php
// Vulnerable counterpart to safe_serializable_magic_method_unserialize.php.
// The enclosing method is named `unserialize` but the call argument is NOT
// the formal parameter — the developer is passing user input directly to
// PHP's `\unserialize()`.  The Serializable magic-method recogniser is
// designed to refuse this shape (the call's argument must be a bare
// reference to the method's single formal parameter).  Must still fire
// `php.deser.unserialize`.

class Mishandled {
    public function unserialize($input): void {
        // BUG: ignores $input, reads from superglobal.
        $this->payload = unserialize($_GET['blob']);
    }
}

class WrappedThenUnserialize {
    // Wrapped argument inside magic method — conservative: still fires.
    // Real-world cache / session pass-throughs surface here so the rule
    // keeps its signal on `unserialize(trim($input))` /
    // `unserialize(base64_decode($input))` shapes.
    public function unserialize($input): void {
        $this->payload = unserialize(trim($input));
    }
}
