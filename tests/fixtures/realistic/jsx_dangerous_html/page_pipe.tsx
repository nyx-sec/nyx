// Phase 06 negative (item 12): `__html` value is `pipe(input, sanitizeHtml,
// DOMPurify.sanitize)`. The fp-ts / Ramda / Lodash composition helper
// recogniser sees `sanitizeHtml` and `DOMPurify.sanitize` in argument
// position and suppresses the synthetic sink's argument-side taint flow.
import DOMPurify from "dompurify";
import { pipe } from "fp-ts/function";
import sanitizeHtml from "sanitize-html";

export function Page({ input }: { input: string }) {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: pipe(input, sanitizeHtml, DOMPurify.sanitize),
      }}
    />
  );
}
