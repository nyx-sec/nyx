//! Call-graph self edges come only from calls on the caller's own instance.
//!
//! A method that calls a same-named method on another object
//! (`super.init(cfg)`, `parent::events()`, `$this->inner->get($k)`,
//! `this.repo.find(id)`, `name.equals(other.name)`) used to resolve to
//! itself, which made the file look self-recursive and sent it through
//! the SCC fixed-point loop.  These tests pin which call shapes produce a
//! self edge and which do not, on real source run through pass 1.

mod common;

use nyx_scanner::ast::extract_all_summaries_from_bytes;
use nyx_scanner::callgraph::{CallGraph, build_call_graph};
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

use common::test_config;

/// Run pass-1 extraction on `(path, source)` pairs and merge the results
/// the way the scanner does before building the call graph.
fn pass1(files: &[(&str, &str)]) -> GlobalSummaries {
    let cfg = test_config(AnalysisMode::Taint);
    let mut funcs = Vec::new();
    let mut ssa = Vec::new();
    for (path, src) in files {
        let (f, s, _bodies, _auth, _cpi, _, _) =
            extract_all_summaries_from_bytes(src.as_bytes(), Path::new(path), &cfg, None)
                .expect("pass-1 extraction must succeed");
        funcs.extend(f);
        ssa.extend(s);
    }
    let mut gs = nyx_scanner::summary::merge_summaries(funcs, None);
    for (k, s) in ssa {
        gs.insert_ssa(k, s);
    }
    gs.install_hierarchy();
    gs
}

/// `(caller, callee)` edges as `file:container::name` strings.
fn edges(cg: &CallGraph) -> Vec<(String, String)> {
    let label = |k: &nyx_scanner::symbol::FuncKey| {
        let file = Path::new(&k.namespace)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("{file}:{}", k.qualified_name())
    };
    let mut out: Vec<(String, String)> = cg
        .graph
        .edge_indices()
        .map(|e| {
            let (a, b) = cg.graph.edge_endpoints(e).unwrap();
            (label(&cg.graph[a]), label(&cg.graph[b]))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Every call site in `gs`, for assertion messages.
fn callee_sites(gs: &GlobalSummaries) -> String {
    let mut rows: Vec<String> = gs
        .iter()
        .flat_map(|(k, s)| {
            s.callees.iter().map(move |c| {
                format!(
                    "{}: name={:?} receiver={:?} qualifier={:?} arity={:?}",
                    k.qualified_name(),
                    c.name,
                    c.receiver,
                    c.qualifier,
                    c.arity
                )
            })
        })
        .collect();
    rows.sort();
    rows.join("\n")
}

fn has_edge(edges: &[(String, String)], from: &str, to: &str) -> bool {
    edges.iter().any(|(a, b)| a == from && b == to)
}

const JAVA_PERSON: &str = r#"package m;
public class Person {
    private String name;
    private Repo repo;
    public boolean equals(Object o) {
        Person other = (Person) o;
        return name.equals(other.name);
    }
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(name);
        return sb.toString();
    }
    public String find(String id) { return repo.find(id); }
    public String lookup(String id) { return this.repo.lookup(id); }
    public int fact(int n) {
        if (n <= 1) { return 1; }
        return n * fact(n - 1);
    }
    public int fact2(int n) {
        if (n <= 1) { return 1; }
        return n * this.fact2(n - 1);
    }
    public static int fact3(int n) {
        if (n <= 1) { return 1; }
        return n * Person.fact3(n - 1);
    }
}
"#;

const JAVA_BASE: &str = r#"package m;
public class Base {
    public void init(String cfg) { System.out.println(cfg); }
}
"#;

const JAVA_SUB: &str = r#"package m;
public class Sub extends Base {
    @Override
    public void init(String cfg) {
        super.init(cfg);
        System.out.println(cfg);
    }
}
"#;

const PHP: &str = r#"<?php
class Base {
    public static function events() { return []; }
}
class Cache extends Base {
    private $inner;
    public static function events() { $e = parent::events(); $e[] = 'x'; return $e; }
    public function get($k) { return $this->inner->get($k); }
    public function walk($x) { return $this->walk($x); }
    public static function walk2($x) { return self::walk2($x); }
    public static function walk3($x) { return static::walk3($x); }
}
"#;

const JS: &str = r#"class Base { init(c) { return c; } }
class Service extends Base {
  constructor(repo) { super(); this.repo = repo; }
  find(id) { return this.repo.find(id); }
  walk(n) { return this.walk(n); }
  init(c) { return super.init(c); }
}
module.exports = Service;
"#;

const PY: &str = r#"import json

class Base:
    def init(self, c):
        return c

class Sub(Base):
    def init(self, c):
        return super().init(c)

    def find(self, i):
        return self.repo.find(i)

    def walk(self, n):
        return self.walk(n)

def dumps(obj):
    return json.dumps(obj)
"#;

const RB: &str = r#"class Finder
  def find(i)
    @repo.find(i)
  end

  def walk(n)
    walk(n)
  end

  def walk2(n)
    self.walk2(n)
  end
end
"#;

const GO: &str = r#"package main

type handler struct{ mux *Mux }

func (h handler) serve(a int) int { return h.serve(a) }

func (h handler) other(a int) int { return h.mux.other(a) }
"#;

fn all_edges() -> (Vec<(String, String)>, GlobalSummaries) {
    let gs = pass1(&[
        ("/p/m/Person.java", JAVA_PERSON),
        ("/p/m/Base.java", JAVA_BASE),
        ("/p/m/Sub.java", JAVA_SUB),
        ("/p/cache.php", PHP),
        ("/p/svc.js", JS),
        ("/p/sub.py", PY),
        ("/p/finder.rb", RB),
        ("/p/main.go", GO),
    ]);
    let cg = build_call_graph(&gs, &[]);
    (edges(&cg), gs)
}

/// A call that only shares the caller's name, made on another object, is
/// not the caller calling itself.
#[test]
fn calls_through_another_object_are_not_self_edges() {
    let (edges, gs) = all_edges();
    for f in [
        "Person.java:Person::equals",
        "Person.java:Person::toString",
        "Person.java:Person::find",
        "Person.java:Person::lookup",
        "Sub.java:Sub::init",
        "cache.php:Cache::events",
        "cache.php:Cache::get",
        "svc.js:Service::find",
        "svc.js:Service::init",
        "sub.py:Sub::init",
        "sub.py:Sub::find",
        "sub.py:dumps",
        "finder.rb:Finder::find",
        "main.go:other",
    ] {
        assert!(
            !has_edge(&edges, f, f),
            "{f} must not get a self edge.\nedges: {edges:#?}\ncallees:\n{}",
            callee_sites(&gs)
        );
    }
}

/// Bare calls and calls on the caller's own instance or class are real
/// self-recursion and keep their self edge.
#[test]
fn calls_on_own_instance_keep_self_edges() {
    let (edges, gs) = all_edges();
    for f in [
        "Person.java:Person::fact",
        "Person.java:Person::fact2",
        "Person.java:Person::fact3",
        "cache.php:Cache::walk",
        "cache.php:Cache::walk2",
        "cache.php:Cache::walk3",
        "svc.js:Service::walk",
        "sub.py:Sub::walk",
        "finder.rb:Finder::walk",
        "finder.rb:Finder::walk2",
        "main.go:serve",
    ] {
        assert!(
            has_edge(&edges, f, f),
            "{f} must keep its self edge.\nedges: {edges:#?}\ncallees:\n{}",
            callee_sites(&gs)
        );
    }
}

/// `super.m()` / `super().m()` / `parent::m()` resolve to the supertype's
/// method through the installed type hierarchy.  (Plain JS `extends` is
/// not recorded in the hierarchy yet, so `svc.js` only checks that its
/// `super.init` is not a self edge.)
#[test]
fn super_calls_resolve_to_the_supertype() {
    let (edges, gs) = all_edges();
    for (from, to) in [
        ("Sub.java:Sub::init", "Base.java:Base::init"),
        ("cache.php:Cache::events", "cache.php:Base::events"),
        ("sub.py:Sub::init", "sub.py:Base::init"),
    ] {
        assert!(
            has_edge(&edges, from, to),
            "{from} must call {to}.\nedges: {edges:#?}\nhierarchy: {:?}\ncallees:\n{}",
            gs.hierarchy(),
            callee_sites(&gs)
        );
    }
}
