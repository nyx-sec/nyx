// Recall guard for `js_browser_components_clean.tsx`: an async App Router
// server component has no hooks and no 'use client' directive, queries the
// database directly with a path param, and still fires.  Pinned in
// `auth_analysis_tests`.
import { prisma } from "@/lib/prisma";

export default async function InvoicePage({ params }: { params: { invoiceId: string } }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.invoiceId } });
  return <div>{invoice?.total}</div>;
}
