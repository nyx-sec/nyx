// Phase 06 recall-gap positive fixture: React JSX `dangerouslySetInnerHTML`
// is the canonical client-side XSS sink in every modern React app, but the
// existing matcher only fires on the property-assignment shape
// (`el.dangerouslySetInnerHTML = x`), which JSX never writes.  The CFG
// builder synthesises a call node from the JSX attribute so taint reaches
// the sink at the `__html: input` line.
export function Page({ input }: { input: string }) {
  return <div dangerouslySetInnerHTML={{ __html: input }} />;
}
