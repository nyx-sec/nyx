// Cal.com-shaped TRPC handler: parameter is a destructured options
// alias (`{ ctx, input }: GetOptions`) where `GetOptions` is a local
// type alias whose `ctx.user` is typed `NonNullable<TrpcSessionUser>`.
// The session-resolved `ctx.user.id` is the authenticated actor;
// composing it with `input.id` in a where-clause is the standard
// owner-eq pattern, NOT a foreign-id targeting flow.
//
// `collect_trpc_ctx_param` (in src/auth_analysis/extract/common.rs)
// must recognise the destructured `ctx` and add `ctx.user` to the
// per-unit `self_scoped_session_bases`, so the auth analyser
// suppresses `missing_ownership_check` on operations rooted at
// `ctx.user.id`.
//
// Marker text in the body of `GetOptions` is what
// `body_text_references_trpc_marker` keys on
// (`TrpcSessionUser`/`TRPCContext`/`ProtectedTRPCContext`/`TrpcContext`).

import { prisma } from "./prisma";

type TrpcSessionUser = { id: number; email: string };

type GetOptions = {
  ctx: { user: NonNullable<TrpcSessionUser> };
  input: { id: number };
};

type ListOptions = {
  ctx: { user: NonNullable<TrpcSessionUser> };
  input: { teamId: number };
};

export const handleGet = async ({ ctx, input }: GetOptions) => {
  return prisma.booking.findFirst({
    where: { id: input.id, userId: ctx.user.id },
  });
};

export const handleList = async ({ ctx, input }: ListOptions) => {
  return prisma.team.findMany({
    where: { id: input.teamId, ownerId: ctx.user.id },
  });
};

// Renamed destructure form: `ctx: c` aliases the trpc context.
type DeleteOptions = {
  ctx: { user: NonNullable<TrpcSessionUser> };
  input: { id: number };
};

export const handleDelete = async ({ ctx: c, input }: DeleteOptions) => {
  return prisma.booking.delete({
    where: { id: input.id, userId: c.user.id },
  });
};

// Plain identifier form: `(opts: GetOptions)` -> `opts.ctx.user`.
export const handleUpdate = async (opts: GetOptions) => {
  return prisma.booking.update({
    where: { id: opts.input.id, userId: opts.ctx.user.id },
    data: { lastSeenAt: new Date() },
  });
};
