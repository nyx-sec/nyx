//! JS/TS runtime facts for the auth extractor: is a unit browser code, server
//! code, or unknown.
//!
//! The ownership rule asks whether a server-side handler authorizes the object
//! it touches.  React components, hooks and SPA helpers run in the browser and
//! cannot enforce that, so they are skipped.  A file is read for its imports
//! and its `'use client'` directive; a unit for hook calls and JSX.  Next.js
//! server components have none of those, so they stay in scope.

use super::common::{named_children, string_literal_value, text};
use crate::auth_analysis::model::{CallSite, UnitRuntime};
use std::collections::HashSet;
use tree_sitter::Node;

/// Modules only a browser bundle imports.  `react-dom/server` and the
/// `next/*` family are left out: both run on the server too.
const CLIENT_MODULES: &[&str] = &[
    "miragejs",
    "ember-cli-mirage",
    "swr",
    "vue",
    "vue-router",
    "pinia",
    "svelte",
    "@apollo/client",
    "zustand",
    "jotai",
    "recoil",
    "formik",
    "antd",
    "styled-components",
    "framer-motion",
    "lucide-react",
    "mobx",
];

/// Packages that run in a browser bundle or in a server component.  A bare
/// `import React from 'react'` does not tell the two apart, so a file counts
/// as browser code only when it also calls a hook (`useEffect`, `useState`),
/// which server components cannot.
const RUNTIME_MODULES: &[&str] = &["react", "preact", "preact/hooks"];

/// Module prefixes that mark a browser bundle: React ecosystem packages
/// (`react-dom`, `react-router`, `react-query`, `react-hook-form`, ...),
/// `@angular/`, UI kits and TanStack's client libraries.
const CLIENT_PREFIXES: &[&str] = &[
    "react-",
    "svelte/",
    "vue/",
    "@vue/",
    "@angular/",
    "@tanstack/",
    "@mui/",
    "@radix-ui/",
    "@headlessui/",
    "@chakra-ui/",
    "@emotion/",
    "mobx-",
];

/// Modules that only run on a server: web frameworks, database clients and
/// Node built-ins.
const SERVER_MODULES: &[&str] = &[
    "express",
    "koa",
    "fastify",
    "hapi",
    "restify",
    "hono",
    "h3",
    "elysia",
    "next/server",
    "next/headers",
    "next/cache",
    "body-parser",
    "passport",
    "mongoose",
    "mongodb",
    "sequelize",
    "typeorm",
    "knex",
    "pg",
    "mysql",
    "mysql2",
    "sqlite3",
    "better-sqlite3",
    "ioredis",
    "redis",
    "@prisma/client",
    "@apollo/server",
    "@trpc/server",
    "graphql-yoga",
    "drizzle-orm",
    "kysely",
    "fs",
    "child_process",
];

const SERVER_PREFIXES: &[&str] = &[
    "@nestjs/",
    "@hapi/",
    "@koa/",
    "@fastify/",
    "koa-",
    "express-",
    "apollo-server",
    "node:",
    "drizzle-orm/",
    "@sequelize/",
];

/// What a file's top-level statements say about where it runs.
#[derive(Debug, Clone, Default)]
pub struct JsFileFacts {
    /// A `'use client'` directive heads the file.
    pub use_client: bool,
    /// The file imports a browser-only module (a React ecosystem package, a
    /// UI kit, a client-side data library).
    pub client_import: bool,
    /// The file imports a web framework, a database client or a Node
    /// built-in.
    pub server: bool,
    /// Local names bound by imports from browser-only modules.
    pub client_bindings: HashSet<String>,
}

pub(super) fn scan_file(root: Node<'_>, bytes: &[u8]) -> JsFileFacts {
    let mut facts = JsFileFacts::default();
    let mut runtime_import = false;
    let mut server_loader = false;
    for stmt in named_children(root) {
        match stmt.kind() {
            "expression_statement" => {
                if let Some(first) = stmt.named_child(0)
                    && let Some(value) = string_literal_value(first, bytes)
                    && value == "use client"
                {
                    facts.use_client = true;
                }
            }
            "export_statement" => {
                if exports_server_loader(stmt, bytes) {
                    server_loader = true;
                }
            }
            "import_statement" => {
                let Some(source) = stmt
                    .child_by_field_name("source")
                    .and_then(|n| string_literal_value(n, bytes))
                else {
                    continue;
                };
                note_module(&source, &mut facts);
                runtime_import |= RUNTIME_MODULES.contains(&source.as_str());
                if is_client_module(&source) {
                    collect_import_bindings(stmt, bytes, &mut facts.client_bindings);
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                for declarator in named_children(stmt) {
                    if let Some(module) = require_module(declarator, bytes) {
                        note_module(&module, &mut facts);
                        runtime_import |= RUNTIME_MODULES.contains(&module.as_str());
                        if is_client_module(&module)
                            && let Some(name) = declarator.child_by_field_name("name")
                        {
                            collect_binding_names(name, bytes, &mut facts.client_bindings);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // A file that also exports a server data loader mixes server and browser
    // code, so a hook call somewhere in it says nothing about the other units.
    if runtime_import && !server_loader && !facts.client_import && file_calls_a_hook(root, bytes) {
        facts.client_import = true;
    }
    facts
}

/// Exports that only run on a server (Next.js and Remix data loaders).
const SERVER_LOADER_EXPORTS: &[&str] = &[
    "getServerSideProps",
    "getStaticProps",
    "getStaticPaths",
    "getInitialProps",
    "loader",
    "action",
    "generateMetadata",
    "generateStaticParams",
];

/// True when an `export` statement declares a server data loader.
fn exports_server_loader(stmt: Node<'_>, bytes: &[u8]) -> bool {
    let Some(decl) = stmt.child_by_field_name("declaration") else {
        return false;
    };
    let named = |n: Node<'_>| {
        n.child_by_field_name("name")
            .is_some_and(|id| SERVER_LOADER_EXPORTS.contains(&text(id, bytes).as_str()))
    };
    match decl.kind() {
        "function_declaration" | "generator_function_declaration" => named(decl),
        "lexical_declaration" | "variable_declaration" => {
            named_children(decl).into_iter().any(named)
        }
        _ => false,
    }
}

/// True when any call in the file is a React hook call.  Only runs for files
/// that import the bare React runtime.
fn file_calls_a_hook(root: Node<'_>, bytes: &[u8]) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && is_hook_name(&text(function, bytes))
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    false
}

fn note_module(module: &str, facts: &mut JsFileFacts) {
    if is_server_module(module) {
        facts.server = true;
    }
    if is_client_module(module) {
        facts.client_import = true;
    }
}

fn is_server_module(module: &str) -> bool {
    SERVER_MODULES.contains(&module) || SERVER_PREFIXES.iter().any(|p| module.starts_with(p))
}

fn is_client_module(module: &str) -> bool {
    // `react-dom/server` renders on a server.
    module != "react-dom/server"
        && (CLIENT_MODULES.contains(&module)
            || CLIENT_PREFIXES.iter().any(|p| module.starts_with(p)))
}

/// `const x = require('mod')` / `const { a } = require('mod')`.
fn require_module(declarator: Node<'_>, bytes: &[u8]) -> Option<String> {
    if declarator.kind() != "variable_declarator" {
        return None;
    }
    let value = declarator.child_by_field_name("value")?;
    if value.kind() != "call_expression" {
        return None;
    }
    let function = value.child_by_field_name("function")?;
    if text(function, bytes) != "require" {
        return None;
    }
    let first = value.child_by_field_name("arguments")?.named_child(0)?;
    string_literal_value(first, bytes)
}

fn collect_import_bindings(stmt: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    for child in named_children(stmt) {
        if child.kind() != "import_clause" {
            continue;
        }
        for part in named_children(child) {
            match part.kind() {
                "identifier" => {
                    out.insert(text(part, bytes));
                }
                "namespace_import" => {
                    for ident in named_children(part) {
                        if ident.kind() == "identifier" {
                            out.insert(text(ident, bytes));
                        }
                    }
                }
                "named_imports" => {
                    for spec in named_children(part) {
                        if spec.kind() != "import_specifier" {
                            continue;
                        }
                        if let Some(local) = spec
                            .child_by_field_name("alias")
                            .or_else(|| spec.child_by_field_name("name"))
                        {
                            out.insert(text(local, bytes));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_binding_names(pattern: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    match pattern.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            out.insert(text(pattern, bytes));
        }
        _ => {
            for child in named_children(pattern) {
                collect_binding_names(child, bytes, out);
            }
        }
    }
}

/// `useState`, `useSidebarLabel`, `useQuery`: the React hook naming
/// convention, which the rules of hooks restrict to components and other
/// hooks.
pub(super) fn is_hook_name(name: &str) -> bool {
    let name = name.rsplit('.').next().unwrap_or(name);
    name.strip_prefix("use")
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// ember-cli-mirage route handler: `function (schema, request)` or
/// `function ({ posts }, { params, queryParams, requestBody })`.  Mirage
/// serves these inside the browser, so they cannot enforce authorization.
/// The destructured second formal is what separates it from an Express
/// handler, whose `(req, res)` pair is never destructured twice.
pub(super) fn is_mirage_handler_signature(function: Node<'_>, bytes: &[u8]) -> bool {
    let Some(params) = function.child_by_field_name("parameters") else {
        return false;
    };
    let formals = named_children(params);
    let [first, second, ..] = formals.as_slice() else {
        return false;
    };
    let (Some(first), Some(second)) = (formal_pattern(*first), formal_pattern(*second)) else {
        return false;
    };
    let first_is_schema = first.kind() == "object_pattern"
        || (first.kind() == "identifier" && text(first, bytes) == "schema");
    if !first_is_schema {
        return false;
    }
    match second.kind() {
        "identifier" => first.kind() == "identifier" && text(second, bytes) == "request",
        "object_pattern" => {
            let mut found = false;
            collect_binding_names_where(second, bytes, &mut |name| {
                found |= matches!(
                    name,
                    "params" | "queryParams" | "requestBody" | "requestHeaders"
                );
            });
            found
        }
        _ => false,
    }
}

fn collect_binding_names_where(pattern: Node<'_>, bytes: &[u8], f: &mut dyn FnMut(&str)) {
    for child in named_children(pattern) {
        match child.kind() {
            "shorthand_property_identifier_pattern" => f(&text(child, bytes)),
            "pair_pattern" => {
                if let Some(key) = child.child_by_field_name("key") {
                    f(&text(key, bytes));
                }
            }
            "object_assignment_pattern" => {
                if let Some(left) = child.child_by_field_name("left") {
                    f(&text(left, bytes));
                }
            }
            _ => {}
        }
    }
}

fn formal_pattern(n: Node<'_>) -> Option<Node<'_>> {
    match n.kind() {
        "required_parameter" | "optional_parameter" => n.child_by_field_name("pattern"),
        _ => Some(n),
    }
}

/// Classify one unit.  `name` is its declared name, `calls` its call sites,
/// `has_jsx` whether its body builds JSX, `is_async` whether the function is
/// declared `async`.
pub(super) fn classify_unit(
    facts: &JsFileFacts,
    name: Option<&str>,
    calls: &[CallSite],
    has_jsx: bool,
    is_async: bool,
) -> UnitRuntime {
    if facts.server {
        return UnitRuntime::Server;
    }
    let calls_hook = calls.iter().any(|call| is_hook_name(&call.name));
    let calls_client_binding = calls.iter().any(|call| {
        let root = call.name.split('.').next().unwrap_or(&call.name);
        facts.client_bindings.contains(root)
    });
    // A synchronous function that returns JSX is a component.  An `async`
    // one is a server component, which may query a database directly.
    let sync_component = has_jsx && !is_async;
    if facts.use_client
        || facts.client_import
        || name.is_some_and(is_hook_name)
        || calls_hook
        || calls_client_binding
        || sync_component
    {
        return UnitRuntime::Browser;
    }
    UnitRuntime::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Language, Parser};

    fn facts(src: &str) -> JsFileFacts {
        let mut parser = Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_typescript::LANGUAGE_TSX))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        scan_file(tree.root_node(), src.as_bytes())
    }

    #[test]
    fn use_client_directive_and_client_imports_are_read() {
        let f = facts(
            "'use client';\nimport { useQuery as q, other } from '@tanstack/react-query';\nimport React from 'react';",
        );
        assert!(f.use_client);
        assert!(f.client_import);
        assert!(!f.server);
        assert!(f.client_bindings.contains("q"));
        assert!(f.client_bindings.contains("other"));
        assert!(!f.client_bindings.contains("React"));
    }

    #[test]
    fn server_imports_win() {
        let f = facts("import express from 'express';\nimport { useState } from 'react-dom';");
        assert!(f.server);
        assert_eq!(
            classify_unit(&f, Some("useThing"), &[], true, false),
            UnitRuntime::Server
        );
        assert!(facts("const { PrismaClient } = require('@prisma/client');").server);
        assert!(!facts("import 'react-dom/server';").use_client);
    }

    #[test]
    fn a_file_that_imports_a_browser_library_is_browser_code() {
        let f = facts("import { type QueryClient } from '@tanstack/react-query';");
        assert_eq!(
            classify_unit(&f, Some("prefetch"), &[], false, false),
            UnitRuntime::Browser
        );
        // Plain `react` is imported by server components too.
        let plain = facts("import React from 'react';");
        assert!(!plain.client_import);
        // A hook call is what only a client module can make.
        let hooked = facts(
            "import {useEffect} from 'react';\nexport const A = () => { useEffect(() => {}); };",
        );
        assert!(hooked.client_import);
        let serverish = facts("import {cache} from 'react';\nexport const q = cache(() => 1);");
        assert!(!serverish.client_import);
        assert_eq!(
            classify_unit(&plain, Some("helper"), &[], false, false),
            UnitRuntime::Unknown
        );
    }

    #[test]
    fn hook_names_follow_the_naming_convention() {
        assert!(is_hook_name("useState"));
        assert!(is_hook_name("React.useEffect"));
        assert!(is_hook_name("useSidebarLabel"));
        assert!(!is_hook_name("use"));
        assert!(!is_hook_name("user"));
        assert!(!is_hook_name("app.use"));
        assert!(!is_hook_name("useless"));
    }

    #[test]
    fn jsx_makes_a_sync_function_a_component_but_not_an_async_one() {
        let f = JsFileFacts::default();
        assert_eq!(
            classify_unit(&f, Some("Title"), &[], true, false),
            UnitRuntime::Browser
        );
        assert_eq!(
            classify_unit(&f, Some("Page"), &[], true, true),
            UnitRuntime::Unknown
        );
        assert_eq!(
            classify_unit(&f, Some("helper"), &[], false, false),
            UnitRuntime::Unknown
        );
    }
}
