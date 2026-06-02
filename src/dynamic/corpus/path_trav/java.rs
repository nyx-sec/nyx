//! Java `Cap::FILE_IO` path-traversal payloads (entry-driven servlet harness).
//!
//! The vulnerable payload escapes the fixture's `testfileDir`
//! (`<workdir>/testfiles/`) one level up to a canary file the harness plants at
//! the workdir root.  The oracle marker is the canary file's CONTENT
//! ([`CANARY_MARKER`]), which is deliberately NOT a substring of the path
//! payload: an OWASP fixture that merely echoes the requested filename back to
//! the response (e.g. `getWriter().write("...'" + fileName + "'...")`) or logs
//! it (`System.out.println(... fileName ...)`) cannot reproduce the marker —
//! only an unsanitised `new FileInputStream(testfileDir + param)` that actually
//! opens and reads the canary does.  This is the FILE_IO analogue of the
//! collision-resistant CODE_EXEC computed marker (`NYX_PWN_791`).
//!
//! The host sandbox (`path_traversal.sb`) denies `/etc/passwd` &c. but allows
//! reads inside the workdir, so the legacy `/etc/passwd` → `root:` rust payload
//! cannot confirm under isolation; the planted canary lives in the readable
//! workdir instead.
//!
//! The benign control names a file that does not exist under `testfileDir`, so
//! the same content-marker oracle cannot fire on it.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

/// Canary filename planted at the harness workdir root (the parent of
/// `testfiles/`).  The Java emitter stages `<workdir>/nyx_pt_canary` with
/// [`CANARY_MARKER`] as its content plus an empty `testfiles/` directory so the
/// `../nyx_pt_canary` traversal resolves.
pub const CANARY_FILENAME: &str = "nyx_pt_canary";

/// Canary file CONTENT — the collision-resistant FILE_IO marker.  Alphanumeric
/// + underscore so a faithful HTML/URL escaper leaves it intact when the
/// fixture writes the read bytes to the response.  NOT a substring of any
/// payload path.
pub const CANARY_MARKER: &str = "NYX_PATHTRAVERSAL_R34D_a7f3c1d8";

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        // `testfileDir + "../nyx_pt_canary"` == `<workdir>/testfiles/../nyx_pt_canary`
        // == `<workdir>/nyx_pt_canary` (the planted canary).
        bytes: b"../nyx_pt_canary",
        label: "path-traversal-canary-java",
        oracle: Oracle::OutputContains(CANARY_MARKER),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 17,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/java/path_traversal/PathTraversalServlet.java",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "path-traversal-benign-java",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        // No traversal and no such file under `testfileDir`, so the canary is
        // never read and the content marker cannot appear.
        bytes: b"nyx_pt_benign_absent_NYX_BENIGN",
        label: "path-traversal-benign-java",
        oracle: Oracle::OutputContains(CANARY_MARKER),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 17,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/java/path_traversal/PathTraversalServlet.java",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
