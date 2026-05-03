// Counterpart to ts-safe-022: an arrow with a REAL handler param named
// `userId` MUST still auto-seed and trigger taint flow into the sink.
// Pins the auto-seed positive path so the FP fix does not over-suppress.

declare const db: { exec: (sql: string) => any };

export const lookupUser = (userId: string) => {
  return db.exec(`SELECT * FROM users WHERE id = '${userId}'`);
};
