use crate::labels::Cap;
use crate::symbol::Lang;

/// A guard rule: functions that must dominate sinks to ensure safety.
pub struct GuardRule {
    pub matchers: &'static [&'static str],
    pub applies_to_sink_caps: Cap,
}

/// An auth rule: functions that perform authentication/authorization checks.
pub struct AuthRule {
    pub matchers: &'static [&'static str],
}

/// An entry point rule: functions that serve as external-facing entry points.
pub struct EntryPointRule {
    pub matchers: &'static [&'static str],
}

/// A resource acquire/release pair.
pub struct ResourcePair {
    pub acquire: &'static [&'static str],
    pub release: &'static [&'static str],
    /// Patterns that look like acquire calls (e.g. `freopen` ends with `fopen`)
    /// but should NOT be treated as acquisitions.
    pub exclude_acquire: &'static [&'static str],
    pub resource_name: &'static str,
    /// Callee patterns that read/write/operate on this specific resource type,
    /// triggering use-after-close if the handle is closed. Checked before the
    /// global `RESOURCE_USE_PATTERNS` fallback.
    pub use_patterns: &'static [&'static str],
}

// ── Guard rules ─────────────────────────────────────────────────────────

static COMMON_GUARDS: &[GuardRule] = &[
    GuardRule {
        matchers: &["validate", "sanitize"],
        applies_to_sink_caps: Cap::all(),
    },
    GuardRule {
        matchers: &["check_", "verify_", "assert_"],
        applies_to_sink_caps: Cap::all(),
    },
    GuardRule {
        matchers: &["shell_escape", "quote", "escape_shell"],
        applies_to_sink_caps: Cap::SHELL_ESCAPE,
    },
    GuardRule {
        matchers: &["html_escape", "encode_safe", "escape_html", "sanitize_html"],
        applies_to_sink_caps: Cap::HTML_ESCAPE,
    },
    GuardRule {
        matchers: &["url_encode", "encode_uri", "urlencode"],
        applies_to_sink_caps: Cap::URL_ENCODE,
    },
    GuardRule {
        matchers: &[
            "which",
            "resolve_binary",
            "find_program",
            "lookup_path",
            "shutil.which",
        ],
        applies_to_sink_caps: Cap::SHELL_ESCAPE,
    },
];

pub fn guard_rules(_lang: Lang) -> &'static [GuardRule] {
    // All languages share the common set for now; per-language
    // overrides can be added via match arms when needed.
    COMMON_GUARDS
}

// ── Auth rules ──────────────────────────────────────────────────────────

static COMMON_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Additional patterns
        "ensureAuthenticated",
        "ensureAuth",
        "requireAuth",
        "hasPermission",
        "requireRole",
    ],
}];

static GO_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        "middleware.auth",
        "auth.required",
        // Additional patterns
        "ensureAuthenticated",
        "ensureAuth",
        "requireAuth",
        "hasPermission",
        "requireRole",
    ],
}];

static JAVA_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        "isAuthenticated",
        "checkPermission",
        "hasAuthority",
        "hasRole",
        // Additional patterns
        "ensureAuthenticated",
        "ensureAuth",
        "requireAuth",
        "hasPermission",
        "requireRole",
        // Spring Security / JAX-RS annotation names (used by decorator
        // detection, see `extract_auth_decorators` in src/cfg.rs).
        "PreAuthorize",
        "PostAuthorize",
        "Secured",
        "RolesAllowed",
        "DenyAll",
        "Authenticated",
    ],
}];

static JS_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // JS/TS middleware & JWT
        "ensureAuthenticated",
        "ensureAuth",
        "requireAuth",
        "hasPermission",
        "requireRole",
        "checkRole",
        "passport.authenticate",
        "jwt.verify",
        // NestJS-style decorators and guard class names (seeded by decorator
        // arg extraction in `extract_auth_decorators`). `UseGuards` alone is
        // too generic, we still match on guard *argument* identifiers here.
        "Authenticated",
        "AuthGuard",
        "JwtAuthGuard",
        "JwtGuard",
        "RolesGuard",
        "SessionGuard",
        "PassportAuthGuard",
    ],
}];

static PYTHON_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Python-specific
        "ensureAuthenticated",
        "ensureAuth",
        "requireAuth",
        "hasPermission",
        "requireRole",
        "login_required",
        "permission_required",
        "has_permission",
        "check_permissions",
        // Common decorator names used by Flask-Login / Django / custom views
        // (consumed by `extract_auth_decorators` on function_definition nodes).
        "admin_required",
        "staff_member_required",
        "user_passes_test",
    ],
}];

static RUBY_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Devise / Rails controller-filter idioms (consumed by `before_action`
        // decorator extraction).
        "authenticate_user",
        "authenticate_admin",
        "require_user",
        "require_admin",
        "current_user",
    ],
}];

static PHP_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Symfony Security attributes (`#[IsGranted(..)]`, `#[Security(..)]`)
        // and common guard idioms.
        "IsGranted",
        "Security",
    ],
}];

static CPP_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Custom C++ attributes, framework-defined, bare-name match.
        "authenticated",
        "require_auth",
        "admin_only",
    ],
}];

static RUST_AUTH: &[AuthRule] = &[AuthRule {
    matchers: &[
        "is_authenticated",
        "require_auth",
        "check_permission",
        "is_admin",
        "authorize",
        "authenticate",
        "require_login",
        "check_auth",
        "verify_token",
        "validate_token",
        // Custom proc-macro attributes, framework-defined, bare-name match.
        "authenticated",
        "require_auth",
        "admin_only",
    ],
}];

/// Boolean authentication predicates that count as a guard only when a branch
/// condition tests them.  A call to one as a statement, or one whose result is
/// stored, enforces nothing: `const authed = req.isAuthenticated();` leaves the
/// handler open.  So these are kept out of [`auth_rules`], which also drives
/// call-statement matching, and are consulted by condition checks alone.
pub fn auth_condition_matchers(lang: Lang) -> &'static [&'static str] {
    match lang {
        // Passport.js `req.isAuthenticated()`.
        Lang::JavaScript | Lang::TypeScript => &["isAuthenticated"],
        _ => &[],
    }
}

pub fn auth_rules(lang: Lang) -> &'static [AuthRule] {
    match lang {
        Lang::Go => GO_AUTH,
        Lang::Java => JAVA_AUTH,
        Lang::JavaScript | Lang::TypeScript => JS_AUTH,
        Lang::Python => PYTHON_AUTH,
        Lang::Ruby => RUBY_AUTH,
        Lang::Php => PHP_AUTH,
        Lang::Cpp => CPP_AUTH,
        Lang::Rust => RUST_AUTH,
        _ => COMMON_AUTH,
    }
}

// ── Entry point rules ───────────────────────────────────────────────────

static COMMON_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
    ],
}];

static GO_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "handler_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
        "ServeHTTP",
    ],
}];

static PYTHON_ENTRY_POINTS: &[EntryPointRule] = &[EntryPointRule {
    matchers: &[
        "main",
        "handle_*",
        "route_*",
        "api_*",
        "serve_*",
        "process_*",
        "view_*",
    ],
}];

pub fn entry_point_rules(lang: Lang) -> &'static [EntryPointRule] {
    match lang {
        Lang::Go => GO_ENTRY_POINTS,
        Lang::Python => PYTHON_ENTRY_POINTS,
        _ => COMMON_ENTRY_POINTS,
    }
}

// ── Resource pairs ──────────────────────────────────────────────────────

/// Match a callee against a resource acquire/release pattern at an identifier
/// boundary.
///
/// A bare-identifier pattern (`connect`, `open`, `alloc`) matches only when the
/// character immediately preceding the matched suffix in the callee is a name
/// separator (not an identifier char).  So `disconnect` / `reconnect` do NOT
/// match `connect`, `register_open` / `_ensure_open` do NOT match `open`, and
/// Rust's release `dealloc` does NOT match acquire `alloc`, all of which the
/// old raw `ends_with` conflated.  Patterns that already carry a leading
/// separator (`.close`, `os.Open`) keep matching by plain suffix.
pub(crate) fn callee_matches_at_boundary(callee_lower: &str, pattern_lower: &str) -> bool {
    if callee_lower == pattern_lower {
        return true;
    }
    if !callee_lower.ends_with(pattern_lower) {
        return false;
    }
    // A pattern whose first char is a separator (`.`, `:`) carries its own
    // left boundary, so no preceding-char check is needed (`f.Close` matches
    // `.Close`).
    if pattern_lower
        .chars()
        .next()
        .map(|c| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(false)
    {
        return true;
    }
    // Bare-identifier pattern: require an identifier boundary before the match.
    let prefix = &callee_lower[..callee_lower.len() - pattern_lower.len()];
    match prefix.chars().next_back() {
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
        None => true,
    }
}

static C_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["malloc", "calloc", "realloc"],
        release: &["free"],
        exclude_acquire: &[],
        resource_name: "memory",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["fopen", "fdopen", "curlx_fopen", "curlx_fdopen"],
        release: &["fclose", "curlx_fclose"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["open"],
        release: &["close"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file descriptor",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["pthread_mutex_lock"],
        release: &["pthread_mutex_unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
];

static CPP_RESOURCES: &[ResourcePair] = &[
    // Inherited from C
    ResourcePair {
        acquire: &["malloc", "calloc", "realloc"],
        release: &["free"],
        exclude_acquire: &[],
        resource_name: "memory",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["fopen", "fdopen", "curlx_fopen", "curlx_fdopen"],
        release: &["fclose", "curlx_fclose"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["open"],
        release: &["close"],
        exclude_acquire: &["freopen", "curlx_freopen"],
        resource_name: "file descriptor",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["pthread_mutex_lock"],
        release: &["pthread_mutex_unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    // C++ new/delete (callee normalized to "new"/"delete" in cfg.rs)
    ResourcePair {
        acquire: &["new"],
        release: &["delete"],
        exclude_acquire: &[],
        resource_name: "heap object",
        use_patterns: &[],
    },
];

static GO_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["os.Open", "os.Create", "os.OpenFile"],
        release: &[".Close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &[".Lock"],
        release: &[".Unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["sql.Open"],
        release: &[".Close"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &[".Query", ".Exec", ".Prepare", ".Begin"],
    },
    ResourcePair {
        acquire: &["net.Listen"],
        release: &[".Close"],
        exclude_acquire: &[],
        resource_name: "listener",
        use_patterns: &[".Accept", ".Addr"],
    },
];

static RUST_RESOURCES: &[ResourcePair] = &[
    // Rust uses RAII, but unsafe alloc/dealloc is a pattern
    ResourcePair {
        acquire: &["alloc"],
        release: &["dealloc"],
        exclude_acquire: &[],
        resource_name: "raw memory",
        use_patterns: &[],
    },
];

// `URL.openConnection()` is deliberately not an acquire here.  A
// `URLConnection` / `HttpURLConnection` has no `close()`: the release is
// closing the stream from `getInputStream()` / `getOutputStream()` (often in a
// try-with-resources) or the optional `disconnect()`, neither of which is a
// release of the connection variable the pair would track.
static JAVA_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["FileInputStream", "FileOutputStream", "BufferedReader"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "stream/connection",
        use_patterns: &[".read", ".write", ".flush", ".available"],
    },
    ResourcePair {
        acquire: &["DriverManager.getConnection", "getConnection"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &[
            ".executeQuery",
            ".executeUpdate",
            ".createStatement",
            ".prepareStatement",
        ],
    },
    ResourcePair {
        // `SocketFactory.createSocket` / `SSLSocketFactory.createSocket`.
        acquire: &["Socket", "createSocket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[".getInputStream", ".getOutputStream", ".connect"],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["prepareStatement"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "prepared statement",
        use_patterns: &[".executeQuery", ".executeUpdate", ".setString", ".setInt"],
    },
    ResourcePair {
        acquire: &["executeQuery"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "result set",
        use_patterns: &[".next", ".getString", ".getInt", ".getBoolean"],
    },
    ResourcePair {
        acquire: &["ServerSocket", "createServerSocket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "server socket",
        use_patterns: &[".accept", ".bind"],
    },
    ResourcePair {
        acquire: &["DatagramSocket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "datagram socket",
        use_patterns: &[".send", ".receive"],
    },
    ResourcePair {
        acquire: &["RandomAccessFile"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "random access file",
        use_patterns: &[".read", ".write", ".seek", ".length"],
    },
    ResourcePair {
        acquire: &["Channel.open", "FileChannel.open", "SocketChannel.open"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "NIO channel",
        use_patterns: &[".read", ".write", ".position"],
    },
];

static PYTHON_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        // `fdopen` / `os.popen` return file objects with `.close()`; they
        // were only caught by the old raw suffix match.  `subprocess.Popen`
        // is deliberately absent: it has no `close()`.
        acquire: &["open", "fdopen", "os.popen"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["socket.socket", "socket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["connect", "cursor"],
        release: &[".close"],
        exclude_acquire: &["signal.connect", "event.connect", ".register"],
        resource_name: "db connection",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["threading.Lock", "threading.RLock"],
        release: &[".release"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["urllib.request.urlopen", "urlopen"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "url handle",
        use_patterns: &[".read", ".readline", ".readlines"],
    },
    ResourcePair {
        acquire: &[
            "http.client.HTTPConnection",
            "HTTPConnection",
            "HTTPSConnection",
        ],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "http connection",
        use_patterns: &[".request", ".getresponse"],
    },
    ResourcePair {
        acquire: &["sqlite3.connect"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "sqlite connection",
        use_patterns: &[".execute", ".cursor", ".commit"],
    },
    ResourcePair {
        acquire: &["tempfile.NamedTemporaryFile", "NamedTemporaryFile"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "temp file",
        use_patterns: &[".write", ".read", ".seek"],
    },
    ResourcePair {
        acquire: &["zipfile.ZipFile", "ZipFile"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "zip file",
        use_patterns: &[".read", ".write", ".extractall", ".namelist"],
    },
];

static RUBY_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["File.open", "File.new", "open", "IO.popen"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "file handle",
        use_patterns: &[
            ".read",
            ".write",
            ".gets",
            ".puts",
            ".each_line",
            ".readline",
            ".readlines",
            ".sysread",
            ".syswrite",
        ],
    },
    ResourcePair {
        acquire: &[
            "TCPSocket.new",
            "UDPSocket.new",
            "TCPServer.new",
            "UNIXSocket.new",
        ],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &[".read", ".write", ".send", ".recv", ".gets", ".puts"],
    },
    ResourcePair {
        acquire: &[".lock"],
        release: &[".unlock"],
        exclude_acquire: &[],
        resource_name: "mutex",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &[
            "PG.connect",
            "PG::Connection.new",
            "Sequel.connect",
            "Mysql2::Client.new",
            "SQLite3::Database.new",
        ],
        release: &[".close", ".disconnect"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &[".exec", ".query", ".exec_params", ".prepare", ".execute"],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["Net::HTTP.start"],
        release: &[".finish"],
        exclude_acquire: &[],
        resource_name: "http connection",
        use_patterns: &[".get", ".post", ".request"],
    },
    ResourcePair {
        acquire: &["Tempfile.new", "Tempfile.open"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "temp file",
        // No `.path`: a closed Tempfile keeps its path until `unlink` /
        // `close!`, and `File.read(tmp.path)` after `close` is the usual
        // idiom.
        use_patterns: &[".write", ".read"],
    },
];

static PHP_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["fopen"],
        release: &["fclose"],
        exclude_acquire: &["freopen"],
        resource_name: "file handle",
        use_patterns: &[],
    },
    ResourcePair {
        acquire: &["mysqli_connect", "mysqli"],
        release: &["mysqli_close", ".close"],
        exclude_acquire: &[],
        resource_name: "db connection",
        use_patterns: &["mysqli_query", "mysqli_fetch_array", ".query", ".fetch"],
    },
    ResourcePair {
        acquire: &["curl_init"],
        release: &["curl_close"],
        exclude_acquire: &[],
        resource_name: "curl handle",
        use_patterns: &["curl_exec", "curl_getinfo", "curl_setopt"],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["pg_connect"],
        release: &["pg_close"],
        exclude_acquire: &[],
        resource_name: "pg connection",
        use_patterns: &["pg_query", "pg_fetch_array", "pg_fetch_row"],
    },
    ResourcePair {
        acquire: &["fsockopen", "pfsockopen"],
        release: &["fclose"],
        exclude_acquire: &[],
        resource_name: "socket",
        use_patterns: &["fwrite", "fread", "fgets"],
    },
    ResourcePair {
        acquire: &["stream_socket_client"],
        release: &["fclose"],
        exclude_acquire: &[],
        resource_name: "stream socket",
        use_patterns: &["fwrite", "fread", "stream_get_contents"],
    },
];

static JS_RESOURCES: &[ResourcePair] = &[
    ResourcePair {
        acquire: &["fs.open", "fs.openSync"],
        release: &["fs.close", "fs.closeSync"],
        exclude_acquire: &[],
        resource_name: "file descriptor",
        use_patterns: &[
            "fs.readSync",
            "fs.writeSync",
            "fs.fstatSync",
            "fs.ftruncateSync",
            "fs.fsyncSync",
        ],
    },
    ResourcePair {
        acquire: &["createReadStream", "createWriteStream"],
        release: &[".close", ".destroy"],
        exclude_acquire: &[],
        resource_name: "stream",
        use_patterns: &[".pipe", ".resume", ".write", ".read", ".push"],
    },
    // Additional patterns
    ResourcePair {
        acquire: &["net.createConnection", "net.connect"],
        release: &[".end", ".destroy"],
        exclude_acquire: &[],
        resource_name: "net socket",
        use_patterns: &[".write", ".read", ".pipe"],
    },
    ResourcePair {
        acquire: &["http.request", "https.request"],
        release: &[".end", ".destroy"],
        exclude_acquire: &[],
        resource_name: "http request",
        use_patterns: &[".write"],
    },
    ResourcePair {
        acquire: &["WebSocket"],
        release: &[".close"],
        exclude_acquire: &[],
        resource_name: "websocket",
        use_patterns: &[".send"],
    },
    ResourcePair {
        acquire: &["mysql.createConnection", "mysql.createPool"],
        release: &[".end", ".destroy"],
        exclude_acquire: &[],
        resource_name: "mysql connection",
        use_patterns: &[".query", ".execute"],
    },
    ResourcePair {
        acquire: &["pg.Pool", "pg.Client"],
        release: &[".end", ".release"],
        exclude_acquire: &[],
        resource_name: "pg connection",
        use_patterns: &[".query"],
    },
];

pub fn resource_pairs(lang: Lang) -> &'static [ResourcePair] {
    match lang {
        Lang::C => C_RESOURCES,
        Lang::Cpp => CPP_RESOURCES,
        Lang::Go => GO_RESOURCES,
        Lang::Rust => RUST_RESOURCES,
        Lang::Java => JAVA_RESOURCES,
        Lang::Python => PYTHON_RESOURCES,
        Lang::Ruby => RUBY_RESOURCES,
        Lang::Php => PHP_RESOURCES,
        Lang::JavaScript | Lang::TypeScript => JS_RESOURCES,
    }
}

// ── JDBC derivation-edge helpers ───────────────────────────────────────
//
// A JDBC `Statement` / `PreparedStatement` / `CallableStatement` is a
// resource *derived* from the `Connection` that produced it: per the JDBC
// contract, closing a `Connection` closes every `Statement` it opened.  So a
// `Statement` whose owning `Connection` is itself a resource this body
// already accounts for (acquired locally — whether closed, borrowed/managed,
// or itself leaking) is never a *unique* true positive:
//   * connection closed in-body        → statement transitively closed (FP);
//   * connection borrowed / managed     → framework closes it → statement
//                                         transitively closed (FP);
//   * connection itself leaks locally   → the connection leak is the single
//                                         actionable root; the derived
//                                         statement is redundant.
// A `Statement` opened on a *long-lived* connection this body does NOT track
// (a field / method parameter / pooled handle held elsewhere) genuinely
// accumulates and stays a leak.  These two helpers implement the derivation
// edge (`ps -> con`) so both the `state::facts` and `cfg_analysis::resources`
// leak passes can apply the same suppression.  Sibling of
// `state::facts::is_jdbc_resultset_acquire` (the leaf `ResultSet` case).

/// Whether `callee` acquires a JDBC `Connection` (`getConnection`).  A
/// borrowed connection (`session.getConnection()`) is still a `getConnection`
/// acquire — the borrowed-vs-owned distinction lives on the acquire node's
/// `borrowed_resource` flag, not here.
pub(crate) fn is_jdbc_connection_acquire(callee: Option<&str>) -> bool {
    let Some(c) = callee else { return false };
    let c = c.to_ascii_lowercase();
    c == "getconnection" || c.ends_with(".getconnection")
}

/// If `callee` acquires a JDBC `Statement` from a `Connection`
/// (`con.prepareStatement(...)` / `con.createStatement()` /
/// `con.prepareCall(...)`), return the receiver connection variable
/// (`con`).  Returns `None` for any other callee, a bare (receiverless)
/// call, or a non-identifier receiver (`this.con`, `getConn().…`) — those do
/// not name a locally-trackable connection variable, so the derived
/// statement is kept as a potential leak.
pub(crate) fn jdbc_statement_owning_connection(callee: Option<&str>) -> Option<&str> {
    let c = callee?;
    let dot = c.rfind('.')?;
    let (recv, leaf) = (&c[..dot], &c[dot + 1..]);
    let leaf_l = leaf.to_ascii_lowercase();
    if leaf_l == "preparestatement" || leaf_l == "createstatement" || leaf_l == "preparecall" {
        // Only a simple identifier receiver names a trackable local var.
        if !recv.is_empty() && !recv.contains('.') && !recv.contains('(') {
            return Some(recv);
        }
    }
    None
}

/// Python DB-API: if `callee` opens a cursor on a connection
/// (`conn.cursor()`), return the receiver connection variable (`conn`).
/// Same contract as [`jdbc_statement_owning_connection`]: only a simple
/// identifier receiver names a locally trackable connection.
pub(crate) fn python_cursor_owning_connection(callee: Option<&str>) -> Option<&str> {
    let c = callee?;
    let (recv, leaf) = c.rsplit_once('.')?;
    if leaf.eq_ignore_ascii_case("cursor")
        && !recv.is_empty()
        && !recv.contains('.')
        && !recv.contains('(')
    {
        return Some(recv);
    }
    None
}

/// Python DB-API connection acquire: any `connect` call
/// (`sqlite3.connect`, `psycopg2.connect`, `pymysql.connect`,
/// `engine.connect`).
pub(crate) fn is_python_connection_acquire(callee: Option<&str>) -> bool {
    callee.is_some_and(|c| {
        c.rsplit('.')
            .next()
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case("connect"))
    })
}

/// A handle derived from a connection whose lifetime it shares: a JDBC
/// `Statement` (`con.prepareStatement`) or a Python DB-API cursor
/// (`conn.cursor()`).  Returns the owning connection variable.  Closing the
/// connection releases what was derived from it, so when that connection is
/// itself tracked in the same body (closed, managed, or leaking on its own)
/// the derived handle is never a unique leak.
pub(crate) fn derived_resource_owner(lang: Lang, callee: Option<&str>) -> Option<&str> {
    match lang {
        Lang::Java => jdbc_statement_owning_connection(callee),
        Lang::Python => python_cursor_owning_connection(callee),
        _ => None,
    }
}

/// Whether `callee` acquires the connection kind [`derived_resource_owner`]
/// derives from in `lang`.
pub(crate) fn is_owning_connection_acquire(lang: Lang, callee: Option<&str>) -> bool {
    match lang {
        Lang::Java => is_jdbc_connection_acquire(callee),
        Lang::Python => is_python_connection_acquire(callee),
        _ => false,
    }
}

#[cfg(test)]
mod jdbc_derivation_tests {
    use super::{
        is_jdbc_connection_acquire, is_python_connection_acquire, jdbc_statement_owning_connection,
        python_cursor_owning_connection,
    };

    #[test]
    fn python_cursor_derivation() {
        assert_eq!(
            python_cursor_owning_connection(Some("conn.cursor")),
            Some("conn")
        );
        assert_eq!(
            python_cursor_owning_connection(Some("self.conn.cursor")),
            None
        );
        assert_eq!(python_cursor_owning_connection(Some("cursor")), None);
        assert_eq!(python_cursor_owning_connection(Some("conn.execute")), None);
        assert!(is_python_connection_acquire(Some("sqlite3.connect")));
        assert!(is_python_connection_acquire(Some("psycopg2.connect")));
        assert!(!is_python_connection_acquire(Some("client.disconnect")));
        assert!(!is_python_connection_acquire(None));
    }

    #[test]
    fn connection_acquire_recognises_getconnection_forms() {
        assert!(is_jdbc_connection_acquire(Some("getConnection")));
        assert!(is_jdbc_connection_acquire(Some("dbSession.getConnection")));
        assert!(is_jdbc_connection_acquire(Some(
            "DriverManager.getConnection"
        )));
        assert!(is_jdbc_connection_acquire(Some("GETCONNECTION")));
        // Not a connection acquire.
        assert!(!is_jdbc_connection_acquire(Some("con.prepareStatement")));
        assert!(!is_jdbc_connection_acquire(Some("getConnectionInfo")));
        assert!(!is_jdbc_connection_acquire(None));
    }

    #[test]
    fn statement_owning_connection_extracts_simple_receiver() {
        assert_eq!(
            jdbc_statement_owning_connection(Some("connection.prepareStatement")),
            Some("connection")
        );
        assert_eq!(
            jdbc_statement_owning_connection(Some("con.createStatement")),
            Some("con")
        );
        assert_eq!(
            jdbc_statement_owning_connection(Some("c.prepareCall")),
            Some("c")
        );
        // Non-identifier receivers name no trackable local: keep the leak.
        assert_eq!(
            jdbc_statement_owning_connection(Some("this.conn.prepareStatement")),
            None
        );
        assert_eq!(
            jdbc_statement_owning_connection(Some("prepareStatement")),
            None
        );
        // Unrelated callees.
        assert_eq!(
            jdbc_statement_owning_connection(Some("ps.executeQuery")),
            None
        );
        assert_eq!(jdbc_statement_owning_connection(None), None);
    }
}
