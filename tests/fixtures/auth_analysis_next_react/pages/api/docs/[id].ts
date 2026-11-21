import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "@/lib/prisma";

// A Next.js API route.  The manifest lists `next` and `react` and no Express,
// Koa or Fastify, so the project names no server framework the route
// extractors know and they must still run.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const doc = await prisma.doc.delete({ where: { id: String(req.query.id) } });
  res.status(200).json(doc);
}
