// Lookalike chains that are not request input.
async function notASource(ctx) {
  const builder = ctx.a.b.req.urlBuilder;
  const base = ctx.a.b.cfg.endpoint;
  await fetch(builder);
  return fetch(base);
}
