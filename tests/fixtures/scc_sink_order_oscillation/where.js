const processNested = (where, ctx) => {
  if (!isRecord(where)) { return where; }
  return processWhere(where, ctx);
};
function processWhere(where, ctx) {
  if (isArray(where)) { return where.map((sub) => processWhere(sub, ctx)); }
  const { qb, alias } = ctx;
  const filters = {};
  for (const key of Object.keys(where)) {
    const value = where[key];
    if (key === '$not') { filters[key] = processNested(value, ctx); continue; }
    if (!value) { filters[qb.aliasColumn(key, alias)] = value; continue; }
    filters[key] = value;
  }
  return filters;
}
