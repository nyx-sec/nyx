// Sources spelled with a receiver chain longer than three segments.
async function viaEvent(event) {
  const target = event.node.req.url;
  return fetch(target);
}

async function viaCtx(ctx) {
  const target = ctx.node.req.url;
  return fetch(target);
}

// `req.urlBuilder` is a different property from `req.url`, and `a.b.cfg`
// is no request chain at all: neither is attacker input.
async function notASource(ctx) {
  const builder = ctx.a.b.req.urlBuilder;
  const base = ctx.a.b.cfg.endpoint;
  await fetch(builder);
  return fetch(base);
}
