// Sources spelled with a receiver chain longer than three segments.
async function viaEvent(event) {
  const target = event.node.req.url;
  return fetch(target);
}

async function viaCtx(ctx) {
  const target = ctx.node.req.url;
  return fetch(target);
}

