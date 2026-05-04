<?php
// Regression for the PHP class-method body analysis fix
// (declaration_list / interface_declaration / trait_declaration mapped to
// Kind::Block in src/labels/php.rs).  Before the fix, taint never crossed
// `class { method { ... } }` because the body of `method` was never
// reached during function extraction, leaving `$_REQUEST → fopen` flows
// inside class methods invisible to taint analysis.  Pairs with
// CVE-2026-33486 (roadiz/documents `DownloadedFile::fromUrl`).

class MediaImporter
{
    public static function fetchRemote(): void
    {
        $url = $_REQUEST['url'];
        fopen($url, 'r');
    }
}
