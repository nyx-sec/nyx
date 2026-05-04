// Vulnerable counterpart to `safe_session_user_id_copy.ts`: the
// `targetUserId` is a foreign id parameter (route param, not the
// caller's session-id copy), so the rule must still flag the missing
// ownership check on the downstream qualified prisma call.
declare const prisma: {
  apiKey: {
    deleteMany(args: { where: { userId: string } }): Promise<void>;
  };
};

export async function deleteApiKeysFromUserId(targetUserId: string) {
  await prisma.apiKey.deleteMany({ where: { userId: targetUserId } });
}
