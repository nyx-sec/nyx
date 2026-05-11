// Same NextAuth options content, but exposed via a factory arrow that
// returns the options object. Matches cal.com's `getOptions` shape:
//
//   export const getOptions = (deps): AuthOptions => ({
//     callbacks: { async signIn(...) { ... }, async jwt(...) { ... } },
//   });
//
// The top-level unit-creation pass attributes every operation inside
// the inner callback methods to the OUTER arrow's unit, because object
// method shorthands are not enumerated as their own units. Without the
// factory-aware suppressor the outer unit name is `getOptions`, not
// `jwt`, so `is_nextauth_callback_unit`'s name match fails and the
// missing-ownership-check rule fires on every identity-resolution
// operation inside the callbacks.

import { prisma } from "./prisma";

type Token = { sub?: string };
type Account = { provider: string };
type Profile = { email?: string };
type User = { id: number; email: string };

export const getOptions = ({
  getDubId,
  getTrackingData,
}: {
  getDubId: () => string | undefined;
  getTrackingData: () => any;
}) => ({
  callbacks: {
    async signIn({ user, account, profile }: { user: User; account: Account; profile: Profile }) {
      await prisma.user.update({
        where: { id: user.id },
        data: { lastSignInProvider: account.provider },
      });
      return true;
    },

    async session({ session, user, token }: { session: any; user: User; token: Token }) {
      const existingUser = await prisma.user.findUnique({ where: { id: user.id } });
      if (!existingUser) return session;
      const profile = await prisma.profile.findUnique({ where: { userId: existingUser.id } });
      session.user = { ...session.user, profileId: profile?.id };
      return session;
    },

    async jwt({ token, user, account }: { token: Token; user?: User; account?: Account }) {
      if (user) {
        const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
        if (dbUser) {
          token.sub = String(dbUser.id);
        }
      }
      return token;
    },
  },
});
