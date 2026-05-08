// Phase 06 positive (item 11): JSX `dangerouslySetInnerHTML={{__html: x}}`
// inside a ternary RHS branch.  Without the synthesis hook in
// `lower_ternary_branch`, this shape is invisible because the wrapping
// `Kind::Assignment` arm short-circuits into `build_ternary_diamond`
// before the JSX subtree is reachable.
import React from "react";

export function Page({ input }: { input: string }) {
  const node = false ? (
    <span>safe</span>
  ) : (
    <div dangerouslySetInnerHTML={{ __html: input }} />
  );
  return node;
}
