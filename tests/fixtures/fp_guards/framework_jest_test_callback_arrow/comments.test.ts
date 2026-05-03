// FP-guard: jest test files use nested arrow callbacks
// (`describe('...', () => { it('...', async () => { ... }) })`).  The
// inner arrow's locals (`body`, `userId`, `server.post`) bubble up to
// the outer arrow as synthetic Params via the call's `taint.uses`.
// Before the fix, JS/TS auto-seed treated every Param whose var_name
// matched a handler-name (e.g. `userId`) as a real formal of the outer
// arrow and seeded it as `Source(UserInput)`, producing phantom
// `taint-unsanitised-flow` findings at every reachable sink.  The fix
// makes `lower_to_ssa_with_params` always treat externals not in the
// (possibly empty) `formal_params` list as synthetic / closure
// captures, so the auto-seed pass skips them.
//
// Distilled from /Users/elipeter/oss/outline/server/routes/api/comments/comments.test.ts
// (934 phantom `taint-unsanitised-flow` findings before the fix).

interface FetchResponse {
  status: number;
  json: () => Promise<unknown>;
}
interface FetchOpts {
  body?: unknown;
}
interface TestServer {
  post: (url: string, opts?: FetchOpts) => Promise<FetchResponse>;
}
interface TestUser {
  id: string;
  teamId: string;
  getJwtToken: () => string;
}
interface TestTeam {
  id: string;
}

declare const server: TestServer;
declare function describe(name: string, fn: () => void): void;
declare function it(name: string, fn: () => Promise<void>): void;
declare function expect<T>(x: T): { toEqual: (other: T) => void };
declare function buildTeam(): Promise<TestTeam>;
declare function buildUser(x: { teamId: string }): Promise<TestUser>;

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
