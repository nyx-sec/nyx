// React components and hooks run in the browser and cannot enforce
// authorization.  Their props are named like ids and they call stores, SDK
// clients and array helpers, none of which is an unchecked server-side data
// access.  Pinned in `auth_analysis_tests`.
import { useTranslation } from "react-i18next";
import { useAdminClient } from "./admin-client";

type Props = { id: string; providerId: string; userId: string };

export const FlowTitle = ({ id, providerId }: Props) => {
  const { providers } = useAuthenticationProvider();
  const helpText = providers?.find((p) => p.id === providerId)?.description;
  return <span data-id={id}>{helpText}</span>;
};

export const UserToggle = ({ userId }: Props) => {
  const { adminClient } = useAdminClient();
  const enable = async () => {
    await adminClient.users.update({ id: userId }, { enabled: true });
  };
  return <button onClick={enable}>Enable</button>;
};

export function useSidebarLabel(documentId?: string) {
  const { documents } = useStores();
  const document = documents.get(documentId);
  return document?.title;
}
