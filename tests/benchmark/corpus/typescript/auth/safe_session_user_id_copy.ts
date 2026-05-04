// Real-repo shape from cal.com Next.js handlers: the authenticated
// `session.user.id` is copied into a local `userId` and used as the
// scoped identifier for a downstream prisma call. The local
// `userId` is the caller's own id (a copy of `session.user.id`,
// recognised as a self-scoped session subject), so the rule must
// not flag.
//
// Closes a 10+ FP cluster on cal.com; the fix lives in
// `src/auth_analysis/extract/common.rs::value_is_self_scoped_session_id_chain`
// which extends `collect_self_actor_id_binding` to recognise
// session-scoped chains beyond the existing `actor_var.id` shape.
declare const prisma: any;
declare function getServerSession(): Promise<any>;

export const Page = async () => {
  const session = await getServerSession();

  if (!session) {
    return null;
  }

  const userId = session.user.id;
  const apiKeys = await prisma.apiKey.findMany({ where: { userId } });
  return apiKeys;
};
