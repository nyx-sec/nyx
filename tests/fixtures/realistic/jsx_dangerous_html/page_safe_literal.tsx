// Phase 06 negative: `__html` is a constant string literal — no taint flows
// into the synthetic sink, so no finding should fire.
export function Hello() {
  return <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;
}
