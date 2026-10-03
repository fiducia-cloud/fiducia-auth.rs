use super::{
    constant_time_eq, internal_secret_authorized, introspect_secret_from, single_header_str,
};
use axum::http::HeaderMap;

#[test]
fn matches_only_on_exact_equality() {
    assert!(constant_time_eq(b"s3cret-value", b"s3cret-value"));
    assert!(!constant_time_eq(b"s3cret-value", b"s3cret-walue"));
    assert!(!constant_time_eq(b"s3cret", b"s3cret-value"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn identity_headers_require_exactly_one_unambiguous_value() {
    let mut headers = HeaderMap::new();
    headers.append("authorization", "Bearer valid.jwt.value".parse().unwrap());
    assert_eq!(
        single_header_str(&headers, "authorization"),
        Some("Bearer valid.jwt.value")
    );

    headers.append(
        "authorization",
        "Bearer attacker.jwt.value".parse().unwrap(),
    );
    assert_eq!(single_header_str(&headers, "authorization"), None);

    let mut coalesced = HeaderMap::new();
    coalesced.insert(
        "authorization",
        "Bearer valid.jwt.value, Bearer attacker.jwt.value"
            .parse()
            .unwrap(),
    );
    assert_eq!(single_header_str(&coalesced, "authorization"), None);
}

#[test]
fn introspection_rejects_duplicate_values_in_both_orders() {
    let secret = "0123456789abcdef0123456789abcdef";
    let mut correct_first = HeaderMap::new();
    correct_first.append("x-server-auth", secret.parse().unwrap());
    correct_first.append("x-server-auth", "attacker".parse().unwrap());
    assert!(!internal_secret_authorized(&correct_first, secret));

    let mut correct_last = HeaderMap::new();
    correct_last.append("x-server-auth", "attacker".parse().unwrap());
    correct_last.append("x-server-auth", secret.parse().unwrap());
    assert!(!internal_secret_authorized(&correct_last, secret));

    let mut exact = HeaderMap::new();
    exact.insert("x-server-auth", secret.parse().unwrap());
    assert!(internal_secret_authorized(&exact, secret));
}

#[test]
fn introspection_secret_configuration_is_strong_and_unambiguous() {
    assert!(introspect_secret_from(None).is_err());
    assert!(introspect_secret_from(Some("short")).is_err());
    let padded = format!(" {}", "x".repeat(32));
    assert!(introspect_secret_from(Some(&padded)).is_err());
    assert!(introspect_secret_from(Some(&"x".repeat(32))).is_ok());
    assert!(introspect_secret_from(Some(&("x".repeat(32) + ",suffix"))).is_err());
    assert!(introspect_secret_from(Some(&("x".repeat(32) + " suffix"))).is_err());
}
