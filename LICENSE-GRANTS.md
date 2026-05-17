# Internal License Grants

This file records dual-licensing grants the copyright holder of Nyx has
issued to specific recipients beyond the public GPL-3.0-or-later release of
this software.

Nyx is distributed publicly under **GPL-3.0-or-later**.  That license
continues to apply to every public release on GitHub, crates.io, and any
other channel.  The grants recorded here are **separate, private licenses**
from the copyright holder to specific projects — they do not modify the
public GPL terms and they are not transferable to third parties.

The right to issue these grants is preserved in `CLA.md`, Section 4
(*Relicensing Right*):

> [The contributor] grants the Project and any entity that maintains or
> succeeds it the right to relicense Your Contribution, in whole or in
> part, under terms other than the Project's current license (currently
> GPL-3.0-or-later), where necessary to support the long-term
> sustainability, distribution, and evolution of the Project.

Because the copyright holder is the sole author of every Contribution to
Nyx (verifiable via `git log`), and the CLA covers any future external
Contributions, the copyright holder may at any time grant any party
(including projects owned by the same copyright holder) a license to use
Nyx under terms other than GPL-3.0-or-later, without affecting the public
GPL release.

## How forks are affected

A third-party fork of Nyx-Pro that obtains the Nyx-Pro source under
PolyForm Small Business 1.0.0 (or any successor source-available license)
does **not** thereby acquire any rights to Nyx beyond the public
GPL-3.0-or-later terms.  The internal grant is project-to-project and
non-transferable.  Anyone redistributing a binary that statically or
dynamically links the `nyx` crate must therefore comply with the GPL on the
`nyx` portion of the work, which is viral copyleft on distribution.  Only
the copyright holder may issue further dual-licensing grants.

---

## Grant Register

### Grant 1 — Nyx Pro (`nyx-agent`)

| Field | Value |
|---|---|
| **Grantor** | Eli Peter (sole copyright holder of Nyx as of the effective date) |
| **Grantee** | The Nyx Pro project (`nyx-agent` daemon, web UI, and accompanying tooling — repository: `nyx-pro`) |
| **Effective date** | 2026-05-17 |
| **Scope** | All Nyx source code, documentation, fixtures, build artefacts, and binaries (the "Licensed Material") in any version released as of the effective date or thereafter, plus any future modifications the Grantor authors or accepts under the CLA |
| **Permitted uses** | (a) static or dynamic linking of the Licensed Material into the Nyx Pro daemon; (b) modification of the Licensed Material as required for Nyx Pro integration; (c) redistribution of the Licensed Material as part of the Nyx Pro distribution; (d) sublicensing the Licensed Material to end users of Nyx Pro solely under whatever license terms Nyx Pro itself is distributed under (currently PolyForm Small Business 1.0.0, or a separately negotiated commercial license) |
| **Restrictions** | (a) this grant does not modify, supersede, or revoke the public GPL-3.0-or-later release of Nyx; (b) this grant is non-transferable — only the Nyx Pro project, owned by the Grantor, may exercise it; (c) any third-party fork of Nyx Pro must obtain Nyx under the public GPL terms, unless it negotiates a separate grant from the Grantor; (d) attribution of Nyx authorship must be preserved in any redistribution per the CLA's moral-rights waiver |
| **Duration** | Perpetual and irrevocable, subject only to the Grantee maintaining ownership-or-control by the Grantor.  If the Nyx Pro project is sold, assigned, or otherwise transferred to a third party, this grant terminates and the new owner must negotiate a separate license |
| **Sublicensing of the grant itself** | Not permitted.  The Grantee may distribute Nyx as part of Nyx Pro to end users under Nyx Pro's outward terms, but the Grantee may not grant any other project the right to use Nyx outside the public GPL terms |
| **Governing law** | Same as Nyx CLA |

---

## Adding future grants

New grants follow the same format as Grant 1.  Append a new section
(`### Grant N — <recipient name>`) below the existing entries and commit
to the Nyx repository.  Grants are append-only; revisions land as
superseding entries with their own date, not as edits to the original.

Grants the Grantor anticipates issuing in the future include:

- Commercial-license SKU grants to individual customers of Nyx Pro that
  exceed the PolyForm Small Business threshold — these will be issued
  per-customer under a separate "Nyx Commercial License" contract;
- Stewardship-transition grants if the project is ever handed off (e.g. to
  a foundation) — these would be a single grant to the receiving entity.

The Grantor reserves the right to refuse to issue any grant.

---

## What this file is NOT

- It is not a redistribution license — third parties cannot rely on it to
  use Nyx outside the public GPL terms.
- It is not a Contributor License Agreement — `CLA.md` covers contribution
  terms separately.
- It is not a public-facing license file — the canonical public license
  for Nyx is `LICENSE` (GPL-3.0-or-later).

---

Copyright © 2026 Eli Peter.  All rights reserved.
