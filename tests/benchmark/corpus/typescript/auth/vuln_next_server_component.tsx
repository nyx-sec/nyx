import { prisma } from "@/lib/prisma";

// Recall guard for safe_browser_components.tsx: an async App Router server
// component has no hooks and no 'use client' directive, and queries the
// database directly with a path param.
export default async function InvoicePage({ params }: { params: { invoiceId: string } }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.invoiceId } });
  return <div>{invoice?.total}</div>;
}
