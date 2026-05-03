// JS counterpart of ts-safe-022.
const { server } = require("./harness");
const { buildUser, buildTeam } = require("./factories");

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
