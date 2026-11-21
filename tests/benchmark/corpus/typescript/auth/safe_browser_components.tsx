import { useTranslation } from "react-i18next";
import { useAdminClient } from "./admin-client";

type Props = { id: string; providerId: string; userId: string };

// React components and hooks run in the browser; their props are named like
// ids and they call SDK clients and array helpers, none of which is an
// unchecked server-side data access.
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
