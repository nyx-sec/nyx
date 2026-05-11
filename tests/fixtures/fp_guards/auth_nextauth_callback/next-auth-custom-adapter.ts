// cal.com NextAuth Adapter factory shape. The function returns the
// Adapter implementation directly, with no `callbacks: { ... }`
// wrapper. Inner method bodies are object method shorthands that
// don't become their own units, so every identity-resolution
// operation inside them accumulates onto the OUTER `CalComAdapter`
// unit. Without the Adapter-shape arm of `body_returns_nextauth_options`,
// `is_nextauth_callback_unit` cannot match by name and the
// missing-ownership rule fires on every `prismaClient.user.findUnique`
// / `prismaClient.account.findUnique` call.

import { prisma } from "./prisma";

type AdapterUser = { id: string; email: string; emailVerified?: Date };
type AdapterAccount = {
  userId: string;
  provider: string;
  providerAccountId: string;
};

const toAdapterUser = (user: { id: number; email: string }): AdapterUser => ({
  id: user.id.toString(),
  email: user.email,
});

const getAccountWhere = (provider: string, providerAccountId: string) => ({
  provider_providerAccountId: { provider, providerAccountId },
});

export default function CalComAdapter(prismaClient: typeof prisma) {
  return {
    createUser: async (data: Omit<AdapterUser, "id">) => {
      const user = await prismaClient.user.create({ data });
      return toAdapterUser(user);
    },

    getUser: async (id: string) => {
      const user = await prismaClient.user.findUnique({ where: { id: parseInt(id, 10) } });
      return user ? toAdapterUser(user) : null;
    },

    getUserByEmail: async (email: string) => {
      const user = await prismaClient.user.findUnique({ where: { email } });
      return user ? toAdapterUser(user) : null;
    },

    async getUserByAccount(providerAccountId: { provider: string; providerAccountId: string }) {
      const account = await prismaClient.account.findUnique({
        where: getAccountWhere(providerAccountId.provider, providerAccountId.providerAccountId),
        select: { user: true },
      });
      return account?.user ? toAdapterUser(account.user) : null;
    },

    updateUser: async (userData: AdapterUser) => {
      const { id, ...data } = userData;
      const user = await prismaClient.user.update({
        where: { id: parseInt(id, 10) },
        data,
      });
      return toAdapterUser(user);
    },

    deleteUser: async (userId: string) => {
      const user = await prismaClient.user.delete({ where: { id: parseInt(userId, 10) } });
      return toAdapterUser(user);
    },

    createVerificationToken: async (data: { identifier: string; token: string; expires: Date }) => {
      const token = await prismaClient.verificationToken.create({ data });
      return token;
    },

    useVerificationToken: async (identifier_token: { identifier: string; token: string }) => {
      const token = await prismaClient.verificationToken.delete({ where: { identifier_token } });
      return token;
    },

    linkAccount: async (account: AdapterAccount) => {
      const created = await prismaClient.account.create({ data: account });
      return created;
    },

    unlinkAccount: async (providerAccountId: Pick<AdapterAccount, "provider" | "providerAccountId">) => {
      const deleted = await prismaClient.account.delete({
        where: getAccountWhere(providerAccountId.provider, providerAccountId.providerAccountId),
      });
      return deleted;
    },

    createSession: async (session: { sessionToken: string; userId: string; expires: Date }) => session,
    getSessionAndUser: async () => null,
    updateSession: async (session: { sessionToken: string }) => ({ sessionToken: session.sessionToken }),
    deleteSession: async () => undefined,
  };
}
