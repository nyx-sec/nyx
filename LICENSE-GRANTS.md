# Internal License Grants

This file records dual-licensing grants the copyright holder of Nyx has issued
beyond the public GPL-3.0-or-later release.

Nyx ships publicly under GPL-3.0-or-later. That license continues to apply to
every public release on GitHub, crates.io, and any other channel. The grants
recorded here are separate, private licenses from the copyright holder to
specific projects. They do not modify the public GPL terms and they are not
transferable to third parties.

The right to issue these grants is preserved in `CLA.md` Section 4
(Relicensing Right):

> [The contributor] grants the Project and any entity that maintains or
> succeeds it the right to relicense Your Contribution, in whole or in part,
> under terms other than the Project's current license (currently
> GPL-3.0-or-later), where necessary to support the long-term sustainability,
> distribution, and evolution of the Project.

The copyright holder is the sole author of every Contribution to Nyx
(verifiable via `git log`). The CLA covers any future external Contributions.
The copyright holder may therefore grant any party, including projects owned
by the same copyright holder, a license to use Nyx under terms other than
GPL-3.0-or-later, without affecting the public GPL release.

## How forks are affected

A third-party fork of Nyctos that obtains the Nyctos source under PolyForm
Small Business 1.0.0 (or any successor source-available license) does not
acquire any rights to Nyx beyond the public GPL-3.0-or-later terms. The
internal grant below is project-to-project and non-transferable. Anyone
redistributing a binary that statically or dynamically links the `nyx` crate
must comply with the GPL on the `nyx` portion of the work. GPL is viral
copyleft on distribution. Only the copyright holder may issue further
dual-licensing grants.

---

## Grant Register

### Grant 1: Nyctos

| Field | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|---|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Grantor | Eli Peter, sole copyright holder of Nyx as of the effective date                                                                                                                                                                                                                                                                                                                                                                                                                |
| Grantee | The Nyctos project (`Nyctos` daemon, web UI, and accompanying tooling). Repository: `nyctos`                                                                                                                                                                                                                                                                                                                                                                                    |
| Effective date | 2026-05-17                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Scope | All Nyx source code, documentation, fixtures, build artefacts, and binaries (the "Licensed Material") in any version released as of the effective date or thereafter, plus any future modifications the Grantor authors or accepts under the CLA                                                                                                                                                                                                                                |
| Permitted uses | (a) static or dynamic linking of the Licensed Material into the Nyctos daemon; (b) modification of the Licensed Material as required for Nyctos integration; (c) redistribution of the Licensed Material as part of the Nyctos distribution; (d) sublicensing the Licensed Material to end users of Nyctos solely under whatever license terms Nyctos itself is distributed under (currently PolyForm Small Business 1.0.0, or a separately negotiated commercial license) |
| Restrictions | (a) this grant does not modify, supersede, or revoke the public GPL-3.0-or-later release of Nyx; (b) this grant is non-transferable; only the Nyctos project, owned by the Grantor, may exercise it; (c) any third-party fork of Nyctos must obtain Nyx under the public GPL terms unless it negotiates a separate grant from the Grantor; (d) attribution of Nyx authorship must be preserved in any redistribution per the CLA's moral-rights waiver                        |
| Duration | Perpetual and irrevocable, subject only to the Grantee maintaining ownership-or-control by the Grantor. If the Nyctos project is sold, assigned, or otherwise transferred to a third party, this grant terminates and the new owner must negotiate a separate license                                                                                                                                                                                                          |
| Sublicensing of the grant itself | Not permitted. The Grantee may distribute Nyx as part of Nyctos to end users under Nyctos's outward terms, but the Grantee may not grant any other project the right to use Nyx outside the public GPL terms                                                                                                                                                                                                                                                                  |
| Governing law | Same as Nyx CLA                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

---

## Adding future grants

New grants follow the same format as Grant 1. Append a new section
(`### Grant N: <recipient name>`) below the existing entries and commit to
the Nyx repository. Grants are append-only. Revisions land as superseding
entries with their own date, not as edits to the original.

Grants the Grantor anticipates issuing in the future include:

- Commercial-license SKU grants to individual customers of Nyctos that
  exceed the PolyForm Small Business threshold. These will be issued
  per-customer under a separate Nyx Commercial License contract.
- Stewardship-transition grants if the project is ever handed off (for
  example, to a foundation). These would be a single grant to the receiving
  entity.

The Grantor reserves the right to refuse to issue any grant.

---

## What this file is NOT

- It is not a redistribution license. Third parties cannot rely on it to use
  Nyx outside the public GPL terms.
- It is not a Contributor License Agreement. `CLA.md` covers contribution
  terms separately.
- It is not a public-facing license file. The canonical public license for
  Nyx is `LICENSE` (GPL-3.0-or-later).

---

Copyright (c) 2026 Eli Peter. All rights reserved.
