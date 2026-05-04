<?php
// Regression for the PHP `if (!validator($x))` early-return narrowing fix
// (src/cfg/mod.rs detect_negation now recognises tree-sitter-php's
// `unary_op_expression` for `!`) PLUS the camelCase normalisation in
// classify_condition (src/taint/path_state.rs to_snake_lower).  Before
// either fix, the camelCase validator name didn't classify as
// ValidationCall, and even if it did, the `!`-prefix wasn't seen as
// negation so the True branch (which is the rejection arm) was treated
// as the validated path, leaving `$url` un-validated past the
// early-return.  Pairs with CVE-2026-33486 patched fixture.

class SafeImporter
{
    public static function fetchRemote(): void
    {
        $url = $_REQUEST['url'];
        if (!self::isSafeRemoteUrl($url)) {
            return;
        }
        // Use file_get_contents (an SSRF sink that doesn't open a long-lived
        // resource) so the regression specifically pins SSRF narrowing
        // without conflating with state-resource-leak from fopen.
        file_get_contents($url);
    }

    private static function isSafeRemoteUrl(string $u): bool
    {
        return true;
    }
}
