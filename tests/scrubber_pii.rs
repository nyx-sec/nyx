//! Phase 28 (Track H.5) — PII scrubber coverage.
//!
//! Asserts that every probe witness textual field is routed through
//! [`nyx_scanner::dynamic::policy::Scrubber`] before serialisation and
//! that the project secret regex set + auxiliary literal substring
//! list catch the common credential / PII shapes that production
//! payloads can splash into a sink call.

#[cfg(feature = "dynamic")]
mod scrubber_pii_tests {
    use nyx_scanner::dynamic::policy::{Scrubber, SCRUB_HASH_PREFIX};
    use nyx_scanner::dynamic::probe::ProbeWitness;

    #[test]
    fn scrubber_recognises_aws_access_key() {
        let s = Scrubber::project_default();
        let value = "AKIAFAKETEST00000000";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX));
        assert!(!out.contains(value));
    }

    #[test]
    fn scrubber_recognises_github_pat() {
        let s = Scrubber::project_default();
        let value = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX));
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn scrubber_recognises_slack_token() {
        let s = Scrubber::project_default();
        let value = "xoxb-1234567890-ABCDEFGHIJK";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX));
    }

    #[test]
    fn scrubber_recognises_openai_sk_token() {
        let s = Scrubber::project_default();
        let value = "sk-1234567890abcdefghijklmnopqr";
        assert!(s.matches_any(value));
    }

    #[test]
    fn scrubber_recognises_bearer_header() {
        let s = Scrubber::project_default();
        let value = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn scrubber_recognises_password_query_param() {
        let s = Scrubber::project_default();
        let value = "?username=eli&password=super_secret_12345";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(!out.contains("super_secret_12345"));
    }

    #[test]
    fn scrubber_recognises_pem_block() {
        let s = Scrubber::project_default();
        let value = "-----BEGIN RSA PRIVATE KEY-----\nMIIEoQIBAAKCAQ\n-----END RSA PRIVATE KEY-----";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(!out.contains("MIIEoQIBAAKCAQ"));
    }

    #[test]
    fn scrubber_recognises_nyx_stub_secret_literal() {
        // Phase 28 acceptance literal.
        let s = Scrubber::project_default();
        let value = "nyx-stub-secret-aaaa-bbbb-cccc";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX));
        assert!(!out.contains("aaaa-bbbb-cccc"));
    }

    #[test]
    fn scrubber_clean_value_round_trips_unchanged() {
        let s = Scrubber::project_default();
        let value = "GET /api/users/42 200 OK";
        assert!(!s.matches_any(value));
        assert_eq!(s.scrub_string(value), value);
    }

    #[test]
    fn scrubber_hash_is_deterministic_across_invocations() {
        let s = Scrubber::project_default();
        let a = s.scrub_string("AKIAFAKETEST00000000");
        let b = s.scrub_string("AKIAFAKETEST00000000");
        assert_eq!(a, b);
    }

    #[test]
    fn scrubber_distinct_inputs_produce_distinct_hashes() {
        let s = Scrubber::project_default();
        let a = s.scrub_string("AKIAFAKETEST00000000");
        let b = s.scrub_string("AKIAFAKETEST11111111");
        assert_ne!(a, b);
    }

    #[test]
    fn probe_witness_args_repr_is_scrubbed_before_telemetry_write() {
        // Phase 28 acceptance: "a probe witness containing a key shaped
        // like `nyx-stub-secret-...` is hashed before telemetry write."
        // ProbeWitness::from_inputs is the host-side constructor every
        // host-built witness travels through; assert the args slot is
        // hashed even when the env / cwd are empty.
        let env: Vec<(String, String)> = vec![];
        let witness = ProbeWitness::from_inputs(
            env,
            "/tmp/run",
            b"payload bytes here",
            "os.system",
            vec!["cmd nyx-stub-secret-deadbeef-feedface".to_owned()],
        );

        let serialised = serde_json::to_string(&witness).unwrap();
        assert!(!serialised.contains("deadbeef-feedface"),
            "raw secret leaked into serialised witness: {serialised}");
        assert!(serialised.contains(SCRUB_HASH_PREFIX),
            "expected scrubbed-hash marker; got {serialised}");
    }

    #[test]
    fn probe_witness_env_value_is_scrubbed() {
        // An env var keyed past the deny-list (so scrub_env keeps the
        // value verbatim) but whose textual value contains a secret
        // pattern must still be hashed by the Phase 28 scrubber pass.
        let env: Vec<(String, String)> = vec![
            ("USER_DATA".to_owned(), "AKIAFAKETEST00000000".to_owned()),
        ];
        let witness = ProbeWitness::from_inputs(
            env, "/x", b"", "fn", vec![],
        );
        let value = witness.env_snapshot.get("USER_DATA").unwrap();
        assert!(value.starts_with(SCRUB_HASH_PREFIX), "got {value}");
    }

    #[test]
    fn probe_witness_args_with_no_secrets_round_trip_unchanged() {
        let env: Vec<(String, String)> = vec![];
        let witness = ProbeWitness::from_inputs(
            env,
            "/tmp/run",
            b"payload",
            "os.system",
            vec!["ls /tmp".to_owned()],
        );
        assert_eq!(witness.args_repr, vec!["ls /tmp".to_owned()]);
    }
}
