// Phase 06 negative: `__html` is the result of `DOMPurify.sanitize(input)`.
// `DOMPurify.sanitize` is a Sanitizer(HTML_ESCAPE), so the synthetic sink
// emits with no argument-side taint flow and stays silent.
import DOMPurify from "dompurify";

export function Page({ input }: { input: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(input) }} />;
}
