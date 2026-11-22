//! Identifier-name predicates shared by the auth analyser.
//!
//! The ownership rules treat an identifier-shaped value as a scoped id when
//! its name looks like one.  A plain `ends_with("id")` test also accepts
//! `grid`, `valid`, `paid`, `android` and `void`, so the match is made on
//! word boundaries instead.

/// English words that end in `id` (or `ids`) and are not identifiers.  Only
/// consulted for names written as a single lowercase or uppercase token, where
/// no snake_case or camelCase boundary says where the word ends.
const NON_ID_WORDS: &[&str] = &[
    "acid",
    "acrid",
    "afraid",
    "aid",
    "amid",
    "android",
    "arid",
    "asteroid",
    "avid",
    "avoid",
    "bid",
    "braid",
    "candid",
    "cupid",
    "devoid",
    "did",
    "druid",
    "flaccid",
    "florid",
    "fluid",
    "forbid",
    "grid",
    "hid",
    "horrid",
    "humanoid",
    "humid",
    "hybrid",
    "insipid",
    "intrepid",
    "invalid",
    "kid",
    "laid",
    "lid",
    "liquid",
    "lucid",
    "lurid",
    "maid",
    "mermaid",
    "mid",
    "morbid",
    "openid",
    "orchid",
    "outbid",
    "overlaid",
    "overpaid",
    "ovoid",
    "paid",
    "placid",
    "prepaid",
    "pyramid",
    "rabid",
    "raid",
    "rapid",
    "rid",
    "rigid",
    "said",
    "solid",
    "sordid",
    "splendid",
    "squalid",
    "squid",
    "steroid",
    "stolid",
    "stupid",
    "tabloid",
    "tepid",
    "thyroid",
    "timid",
    "torpid",
    "turbid",
    "typhoid",
    "underpaid",
    "unpaid",
    "unsaid",
    "valid",
    "vapid",
    "vid",
    "vivid",
    "void",
];

/// One-letter stems for the common abbreviations (`uid`, `gid`, `pid`, ...).
/// Every other single-letter stem is an ordinary word (`aid`, `bid`, `kid`).
const ABBREVIATION_STEMS: &[char] = &['u', 'g', 'p', 'o', 'c', 's', 't', 'f', 'e', 'n', 'x'];

/// Suffixes that mark a camelCase or PascalCase identifier.  The character
/// before the suffix must be a lowercase letter or a digit, which keeps
/// `userId` and `repoIDs` and leaves `GRID` and `Android` alone.
const CAMEL_ID_SUFFIXES: &[&str] = &[
    "Id", "ID", "Ids", "IDs", "Uid", "UID", "Uuid", "UUID", "Guid", "GUID",
];

/// Names that are an identifier on their own.
const BARE_ID_NAMES: &[&str] = &["id", "ids", "uid", "uids", "uuid", "uuids", "guid", "guids"];

/// True when `name` reads as an identifier: `id`, `user_id`, `userId`,
/// `userID`, `UserIDs`, `userid`.  Words that merely end in the letters `id`
/// (`grid`, `valid`, `paid`, `android`, `void`) are not.
pub fn is_id_like_name(name: &str) -> bool {
    let name = name.trim_start_matches(['@', '$', '&', '*', ':']);
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if BARE_ID_NAMES.contains(&lower.as_str()) {
        return true;
    }
    if lower.ends_with("_id")
        || lower.ends_with("-id")
        || lower.ends_with("_ids")
        || lower.ends_with("-ids")
        || lower.ends_with("_uuid")
        || lower.ends_with("_uid")
        || lower.ends_with("_guid")
    {
        return true;
    }
    if has_camel_id_suffix(name) {
        return true;
    }
    if lower.contains("workspaceid") || lower.contains("projectid") || lower.contains("noteid") {
        return true;
    }
    is_single_token_id(name, &lower)
}

/// True when `name` is an id-like name that holds several ids: `ids`,
/// `user_ids`, `userIds`, `UserIDs`.
pub fn is_id_collection_name(name: &str) -> bool {
    is_id_like_name(name) && name.to_ascii_lowercase().ends_with("ids")
}

/// True for `uid`, `targetUid`, `componentUID`, `content_type_uid`.  In many
/// codebases (Strapi is the common one) a `uid` is a schema selector such as
/// `api::article.article`, not a row id.  `uuid` is a real identifier and does
/// not match.
pub fn is_uid_name(name: &str) -> bool {
    let name = name.trim_start_matches(['@', '$', '&', '*', ':']);
    let lower = name.to_ascii_lowercase();
    if lower == "uid" || lower.ends_with("_uid") || lower.ends_with("-uid") {
        return true;
    }
    ["Uid", "UID"].iter().any(|suffix| {
        name.strip_suffix(suffix).is_some_and(|stem| {
            stem.chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
    })
}

fn has_camel_id_suffix(name: &str) -> bool {
    CAMEL_ID_SUFFIXES.iter().any(|suffix| {
        name.strip_suffix(suffix).is_some_and(|stem| {
            stem.chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
    })
}

/// The `userid` / `docid` / `USERID` shape: one token with no case or
/// delimiter boundary.  Accepted unless the whole word is ordinary English.
fn is_single_token_id(name: &str, lower: &str) -> bool {
    let single_case = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    if !single_case {
        return false;
    }
    let (stem, singular) = if let Some(stem) = lower.strip_suffix("ids") {
        (stem, &lower[..lower.len() - 1])
    } else if let Some(stem) = lower.strip_suffix("id") {
        (stem, lower)
    } else {
        return false;
    };
    if stem.is_empty() || NON_ID_WORDS.contains(&singular) {
        return false;
    }
    let mut chars = stem.chars();
    match (chars.next(), chars.next()) {
        (Some(only), None) => ABBREVIATION_STEMS.contains(&only),
        _ => true,
    }
}

/// Recognises parameter names that conventionally carry a *scope*
/// entity, the multi-tenant ownership boundary inherited from the
/// caller, rather than a user-controlled target identifier.  Used
/// only by `is_caller_scope_entity_subject` to suppress
/// `missing_ownership_check` on `<entity>.id` arguments to ORM /
/// query / mutation calls.
///
/// Vocabulary matches the canonical multi-tenant primitives across
/// Django (Sentry, Saleor), Rails (Discourse, Mastodon), and Laravel
/// /  Symfony idioms.  Both singular and short forms are matched
/// (`organization` / `org`, `repository` / `repo`).  Excluded:
/// `user`, `member`, `actor` (actor semantics, covered by
/// `is_actor_context_subject` and per-actor self-id detectors).
pub(super) fn is_caller_scope_entity_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "organization"
            | "org"
            | "project"
            | "team"
            | "workspace"
            | "tenant"
            | "account"
            | "community"
            | "group"
            | "repository"
            | "repo"
            | "company"
    )
}

pub(super) fn is_request_scope_segment(segment: &str) -> bool {
    is_caller_scope_entity_name(segment)
        || matches!(
            segment.to_ascii_lowercase().as_str(),
            "package" | "owner" | "contextuser"
        )
}

pub(super) fn is_request_payload_segment(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        "body"
            | "form"
            | "postform"
            | "multipartform"
            | "query"
            | "params"
            | "input"
            | "data"
            | "req"
            | "request"
            | "header"
            | "headers"
            | "url"
            | "args"
            | "json"
            | "values"
    )
}

/// True when the path segments after a request-context root (`Repo.GitRepo`
/// in `ctx.Repo.GitRepo`) name a scope entity the middleware resolved and do
/// not pass through request payload.
pub(super) fn is_request_scope_path(rest: &[&str]) -> bool {
    rest.iter().any(|seg| is_request_scope_segment(seg))
        && !rest.iter().any(|seg| is_request_payload_segment(seg))
}

/// Chains that hold the server-side (or signed) session of the caller.
const SESSION_CONTAINERS: &[&str] = &[
    "session",
    "req.session",
    "request.session",
    "ctx.session",
    "self.session",
    "flask.session",
    "ctx.state",
];

/// Prefixes a login flow puts before the identity key while the caller is
/// between password and second factor (`twofaUid`, `twoFactorUserID`).  The
/// server writes the id once the first factor has passed, so it still names
/// the person signing in.
const SESSION_FLOW_PREFIXES: &[&str] = &["twofactor", "twofa", "2fa", "mfa", "preauth", "login"];

/// Identity keys of a session store, compared after dropping case and
/// punctuation.  The match is exact, not by suffix: `impersonated_user_id`,
/// `workspace_id` and `cart_id` name some other row and stay request-grade.
const SESSION_IDENTITY_KEYS: &[&str] = &["userid", "uid", "currentuserid", "accountid", "memberid"];

/// True when `key` names the authenticated caller's own id in a session store:
/// `user_id`, `userId`, `uid`, `current_user_id`, `account_id`, `member_id`,
/// optionally behind a login-flow prefix (`twofaUid`).
pub(super) fn is_session_identity_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if SESSION_IDENTITY_KEYS.contains(&norm.as_str()) {
        return true;
    }
    SESSION_FLOW_PREFIXES.iter().any(|prefix| {
        norm.strip_prefix(prefix)
            .is_some_and(|rest| SESSION_IDENTITY_KEYS.contains(&rest))
    })
}

/// `req.session.userId`, `session.user_id`, `request.session.uid`: a session
/// container followed by exactly one identity key.
pub(super) fn is_session_identity_ref(chain: &str) -> bool {
    let Some((container, key)) = chain.rsplit_once('.') else {
        return false;
    };
    SESSION_CONTAINERS.contains(&container.to_ascii_lowercase().as_str())
        && is_session_identity_key(key)
}

/// The receiver of a session-store read (`ctx.Session`, `sess`, `session`,
/// `request.session`): a known container, or a name that ends in `session` /
/// `sess`, which is how a Go handler aliases the store it fetched.
pub(super) fn is_session_store_receiver(receiver: &str) -> bool {
    let lower = receiver.to_ascii_lowercase();
    if SESSION_CONTAINERS.contains(&lower.as_str()) {
        return true;
    }
    let last = lower.rsplit('.').next().unwrap_or(&lower);
    matches!(last, "session" | "sess")
}

/// Chains that name the authenticated caller itself.  `current_user` and
/// `current_account` are the Devise / Flask-Login / Rails helpers; the rest are
/// the request-bound user of Django, Express, Koa and Flask.
pub(super) fn is_actor_object(chain: &str) -> bool {
    matches!(
        chain,
        "current_user"
            | "current_account"
            | "current_member"
            | "User.current"
            | "g.user"
            | "self.request.user"
            | "req.user"
            | "request.user"
            | "req.currentUser"
            | "request.currentUser"
            | "ctx.state.user"
            | "ctx.state.currentUser"
            | "ctx.state.auth.user"
            | "ctx.session.user"
            | "session.user"
    )
}

/// Parameter names that carry the authenticated caller into a resolver or
/// helper (`requestor`, `requester`, `viewer`).  A name is only a convention,
/// so this is used to read an argument as the caller, never to exempt a
/// request-supplied id.
pub(super) fn is_caller_identity_name(name: &str) -> bool {
    matches!(name, "requestor" | "requester" | "viewer")
}

/// Text of an expression that names the authenticated caller or its own id:
/// `current_user`, `request.user`, `requestor`, `requester.id`,
/// `current_user.pk`.
pub(super) fn is_actor_ref_text(text: &str) -> bool {
    let text = text.trim();
    if is_actor_object(text) || is_caller_identity_name(text) {
        return true;
    }
    text.rsplit_once('.').is_some_and(|(base, field)| {
        (is_actor_object(base) || is_caller_identity_name(base))
            && matches!(
                field.to_ascii_lowercase().as_str(),
                "id" | "pk" | "user_id" | "userid" | "uid"
            )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        is_id_collection_name, is_id_like_name, is_session_identity_key, is_session_identity_ref,
        is_uid_name,
    };

    #[test]
    fn identifier_shapes_are_id_like() {
        for name in [
            "id",
            "ID",
            "Id",
            "ids",
            "uid",
            "uuid",
            "user_id",
            "userId",
            "userID",
            "UserID",
            "USER_ID",
            "user-id",
            "userIds",
            "userIDs",
            "user_ids",
            "UserIDs",
            "repoID",
            "targetUid",
            "userid",
            "docid",
            "orgid",
            "@user_id",
            "$userId",
            "@id",
            ":id",
            ":user_id",
            "workspaceidx",
            "sid",
            "pid",
            "oid",
            "USERID",
        ] {
            assert!(is_id_like_name(name), "{name} should be id-like");
        }
    }

    #[test]
    fn words_ending_in_id_are_not_id_like() {
        for name in [
            "grid", "valid", "invalid", "paid", "unpaid", "prepaid", "android", "void", "avoid",
            "fluid", "rapid", "hybrid", "said", "mid", "kid", "bid", "aid", "did", "openid",
            "GRID", "Android", "isValid", "tlsValid", "grids", "kids", "androids", "fluids",
            "Void", "liquid", "solid", "",
        ] {
            assert!(!is_id_like_name(name), "{name} should not be id-like");
        }
    }

    #[test]
    fn collection_names_end_in_ids() {
        assert!(is_id_collection_name("ids"));
        assert!(is_id_collection_name("user_ids"));
        assert!(is_id_collection_name("uniqueIDs"));
        assert!(is_id_collection_name("endpointIds"));
        assert!(!is_id_collection_name("userId"));
        assert!(!is_id_collection_name("grids"));
        assert!(!is_id_collection_name("kids"));
    }

    #[test]
    fn uid_names_are_schema_selectors_not_uuids() {
        for name in [
            "uid",
            "UID",
            "targetUid",
            "componentUID",
            "content_type_uid",
        ] {
            assert!(is_uid_name(name), "{name} should be a uid name");
        }
        for name in ["uuid", "userId", "guid", "fluid", "uidx", "valid", ""] {
            assert!(!is_uid_name(name), "{name} should not be a uid name");
        }
    }

    #[test]
    fn session_identity_keys_are_exact() {
        for key in [
            "user_id",
            "userId",
            "UID",
            "uid",
            ":user_id",
            "current_user_id",
            "account_id",
            "member_id",
            "twofaUid",
            "twoFactorUserID",
        ] {
            assert!(is_session_identity_key(key), "{key} should be identity");
        }
        for key in [
            "workspace_id",
            "impersonated_user_id",
            "cart_id",
            "project_id",
            "user",
            "id",
            "target_user_id",
            "",
        ] {
            assert!(
                !is_session_identity_key(key),
                "{key} should not be identity"
            );
        }
        assert!(is_session_identity_ref("session.user_id"));
        assert!(is_session_identity_ref("request.session.uid"));
        assert!(!is_session_identity_ref("session.workspace_id"));
        assert!(!is_session_identity_ref("req.query.userId"));
    }
}
