// FP-guard regression for the jest-test-callback shape that 934'd outline:
// nested arrow callbacks (`it("...", async () => { const body = ... })`)
// passed to `it()` / `describe()` capture free vars (`body`, `userId`,
// `server`).  Those free vars bubble up to the OUTER arrow's body as
// `taint.uses` of the `it(...)` call and become synthetic `Param`s in the
// SSA for the outer arrow.  Before the fix, the auto-seed pass treated
// every `Param` whose `var_name` matched a handler-name like `userId` /
// `cmd` as a real formal param of the outer arrow and seeded it as a
// `Source(UserInput)`, producing phantom `taint-unsanitised-flow`
// findings at every sink reachable from the outer arrow's body (e.g.
// `server.post`, `res.json`).
//
// The fix makes `lower_to_ssa_with_params` (the per-function lowering)
// always treat externals not in the supplied `formal_params` as
// synthetic / closure-captured, even when the formal list is empty
// (arrow `() => {…}`).  See `src/ssa/lower.rs::lower_to_ssa_inner`
// `with_params` flag.

declare const server: { post: (url: string, body?: any) => Promise<any> };
declare function describe(name: string, fn: () => void): void;
declare function it(name: string, fn: () => Promise<void>): void;
declare function expect(x: any): any;
declare function buildTeam(): Promise<any>;
declare function buildUser(x: any): Promise<any>;

describe("#comments.list", () => {
  it("should require auth", async () => {
    const res = await server.post("/api/comments.list");
    const body = await res.json();
    expect(res.status).toEqual(401);
  });

  it("should list comments", async () => {
    const team = await buildTeam();
    const user = await buildUser({ teamId: team.id });
    const res = await server.post("/api/comments.list", {
      body: {
        token: user.getJwtToken(),
        id: user.id,
      },
    });
    const body = await res.json();
    expect(res.status).toEqual(200);
  });
});
