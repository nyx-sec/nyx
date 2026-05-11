import { escapeHtmlNoop } from "@scope/util/sanitize";
import { stripTags } from "@scope/util/strip";

export function unsafeHandler(req: any, res: any) {
  const x = req.query.x;
  const y = escapeHtmlNoop(x);
  res.send(y);
}

export function safeHandler(req: any, res: any) {
  const x = req.query.x;
  const y = stripTags(x);
  res.send(y);
}
