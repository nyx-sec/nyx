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

#[cfg(test)]
mod tests {
    use super::{is_id_collection_name, is_id_like_name, is_uid_name};

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
}
