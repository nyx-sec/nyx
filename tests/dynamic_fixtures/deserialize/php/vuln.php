<?php
// Phase 03 (Track J.1) — PHP deserialize vuln fixture.
//
// `unserialize` without `allowed_classes` will materialise any
// `O:N:"ClassName":` blob the attacker sends, triggering `__wakeup`
// / `__destruct` chains.
function run(string $blob) {
    return unserialize($blob);
}
