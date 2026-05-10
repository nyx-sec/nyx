// FP guard for cal.com-shape post-fetch ownership equality checks
// in JS/TS Next.js page handlers.
//
// The handler fetches a row by id, then verifies the row's owner field
// matches the session user via strict-inequality.  Failure calls the
// framework denial helper (notFound, redirect, forbidden, unauthorized)
// to terminate the request.  This shape is canonical post-fetch
// authorization across cal.com and other Next.js codebases.
//
// Pre-fix the engine missed this for three reasons:
// 1. detect_ownership_equality_check only ran for if_expression (Rust),
//    not if_statement (JS/TS/Java/Python/Go/PHP).
// 2. is_ne / is_eq matched "!=" / "==" but not the JS/TS strict variants
//    "!==" / "===".
// 3. branch_has_early_exit only matched return / throw.  notFound() and
//    similar Next.js denial helpers are call_expression and were
//    invisible.
// 4. collect_row_population only read pattern/left, missing the
//    JS/TS variable_declarator name field.
//
// Each shape below exercises one column of the matrix.

import { notFound, redirect, unauthorized, forbidden } from "next/navigation";

declare class WebhookRepository {
  static getInstance(): WebhookRepository;
  findByWebhookId(id: string | undefined): Promise<{ userId: number }>;
}

declare function getServerSession(): Promise<{ user?: { id: number } } | null>;

// 1. notFound() denial in if_statement with !== strict inequality.
export async function pageNotFound({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId !== session.user.id) {
    notFound();
  }
  return webhook;
}

// 2. redirect() denial.
export async function pageRedirect({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId !== session.user.id) {
    redirect("/login");
  }
  return webhook;
}

// 3. unauthorized() denial.
export async function pageUnauthorized({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId !== session.user.id) {
    unauthorized();
  }
  return webhook;
}

// 4. forbidden() denial.
export async function pageForbidden({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId !== session.user.id) {
    forbidden();
  }
  return webhook;
}

// 5. throw on the failure branch.
export async function pageThrow({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId !== session.user.id) {
    throw new Error("not authorized");
  }
  return webhook;
}

// 6. === inverted equality with else { notFound() }.
export async function pageEqElse({ params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user?.id) return null;
  const repo = WebhookRepository.getInstance();
  const webhook = await repo.findByWebhookId(params.id);
  if (webhook.userId === session.user.id) {
    return webhook;
  } else {
    notFound();
  }
}
