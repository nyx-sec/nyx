//! Phase 11 — Track D.5: [`NetworkPolicy`] acceptance.
//!
//! These tests exercise the public API surface; they do *not* drive a
//! real container.  The docker backend's per-variant flag emission is
//! covered indirectly by `tests/dynamic_sandbox_escape.rs` (which still
//! pins `NetworkPolicy::None`), and the Linux iptables filter path is
//! covered by `src/dynamic/sandbox.rs` unit tests.
//!
//! Scope here is structural: each variant exposes the right accessor
//! shape, the default is `None`, and [`SandboxOptions::oob_listener`]
//! still resolves the legacy callsite without the runner caring which
//! variant fed it.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::oob::OobListener;
use nyx_scanner::dynamic::sandbox::{HostPort, NetworkPolicy, SandboxOptions};
use std::sync::Arc;

#[test]
fn default_policy_is_none() {
    let opts = SandboxOptions::default();
    assert!(matches!(opts.network_policy, NetworkPolicy::None));
    assert!(opts.oob_listener().is_none());
}

#[test]
fn none_blocks_network() {
    let p = NetworkPolicy::None;
    assert!(!p.allows_network());
    assert!(p.oob_listener().is_none());
    assert!(p.stub_allow_list().is_none());
    assert_eq!(p.variant_tag(), "none");
}

#[test]
fn stubs_only_carries_allowlist() {
    let p = NetworkPolicy::StubsOnly {
        allow: vec![
            HostPort::new("db.local", 5432),
            HostPort::new("redis.local", 6379),
        ],
    };
    assert!(p.allows_network());
    assert!(p.oob_listener().is_none());
    let allow = p.stub_allow_list().expect("allow list present");
    assert_eq!(allow.len(), 2);
    assert_eq!(allow[0].host, "db.local");
    assert_eq!(allow[0].port, 5432);
    assert_eq!(p.variant_tag(), "stubs-only");
}

#[test]
fn oob_outbound_carries_listener() {
    // Skip on hosts where loopback bind is impossible (e.g. extremely
    // locked-down sandboxes).  All other CI hosts can bind 127.0.0.1.
    let Ok(listener) = OobListener::bind() else {
        eprintln!("OobListener::bind failed — skipping oob_outbound_carries_listener");
        return;
    };
    let listener = Arc::new(listener);
    let p = NetworkPolicy::OobOutbound {
        listener: Arc::clone(&listener),
    };
    assert!(p.allows_network());
    let got = p.oob_listener().expect("listener present");
    assert!(
        Arc::ptr_eq(got, &listener),
        "oob_listener() must return the same Arc"
    );
    assert!(p.stub_allow_list().is_none());
    assert_eq!(p.variant_tag(), "oob-outbound");
}

#[test]
fn open_allows_network_with_no_filter() {
    let p = NetworkPolicy::Open;
    assert!(p.allows_network());
    assert!(p.oob_listener().is_none());
    assert!(p.stub_allow_list().is_none());
    assert_eq!(p.variant_tag(), "open");
}

#[test]
fn sandbox_options_oob_listener_accessor_finds_oob_variant() {
    let Ok(listener) = OobListener::bind() else {
        eprintln!("OobListener::bind failed — skipping accessor test");
        return;
    };
    let listener = Arc::new(listener);
    let opts = SandboxOptions {
        network_policy: NetworkPolicy::OobOutbound {
            listener: Arc::clone(&listener),
        },
        ..SandboxOptions::default()
    };
    let got = opts.oob_listener().expect("listener present");
    assert!(Arc::ptr_eq(got, &listener));
}

#[test]
fn sandbox_options_oob_listener_accessor_none_for_other_variants() {
    let opts_none = SandboxOptions {
        network_policy: NetworkPolicy::None,
        ..SandboxOptions::default()
    };
    assert!(opts_none.oob_listener().is_none());

    let opts_open = SandboxOptions {
        network_policy: NetworkPolicy::Open,
        ..SandboxOptions::default()
    };
    assert!(opts_open.oob_listener().is_none());

    let opts_stubs = SandboxOptions {
        network_policy: NetworkPolicy::StubsOnly { allow: vec![] },
        ..SandboxOptions::default()
    };
    assert!(opts_stubs.oob_listener().is_none());
}
