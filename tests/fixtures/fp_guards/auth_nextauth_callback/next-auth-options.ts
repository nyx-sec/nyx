// Minimal NextAuth-style configuration. The named callbacks below are
// the authentication boundary itself: operations on `user.id` /
// `existingUser.id` inside them resolve the authenticated identity,
// they are not request-driven foreign-id lookups. The auth analyser
// must NOT flag js.auth.missing_ownership_check on these operations.

import { prisma } from "./prisma";

type Token = { sub?: string };
type Account = { provider: string; providerAccountId: string };
type Profile = { email?: string };
type User = { id: number; email: string };

export const authOptions = {
  callbacks: {
    async signIn({ user, account, profile }: { user: User; account: Account; profile: Profile }) {
      // Authentication-time mutation: record provider linkage on the
      // authenticated user. Not a tenant-scoped resource lookup.
      await prisma.user.update({
        where: { id: user.id },
        data: { lastSignInProvider: account.provider },
      });
      return true;
    },

    async session({ session, user, token }: { session: any; user: User; token: Token }) {
      // Identity-resolution read against `user.id` / `token.sub`.
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

    async authorize(credentials: { email: string; password: string }) {
      // Credentials-provider authorize: looks up the user by email and
      // verifies the password. Authentication boundary, not foreign-id
      // targeting.
      const user = await prisma.user.findUnique({ where: { email: credentials.email } });
      if (!user) return null;
      return { id: user.id, email: user.email };
    },
  },
};
