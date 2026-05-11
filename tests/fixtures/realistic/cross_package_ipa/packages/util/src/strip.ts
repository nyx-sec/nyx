// Cross-package fixture for Phase 09: sanitizer that wraps the JS
// intrinsic `encodeURIComponent` (recognised by the JS sanitizer label
// table as `Sanitizer(URL_ENCODE | HTML_ESCAPE)`).  The intra-file SSA
// summary therefore carries a real sanitize transform on `s → return`,
// which step 0.7 of `resolve_callee_full` propagates into the caller
// site so the cross-package safe path stays silent.
export function stripTags(s: string): string {
  return encodeURIComponent(s);
}
