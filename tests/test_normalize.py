"""Unit tests for the request normalizer — the highest-bug-risk pure logic in v1."""

import pytest

from secagent.normalize import (
    extract_param_names,
    normalize_path,
    normalize_segment,
    signature,
)

UUID = "9f8b2c1a-1234-4abc-8def-0123456789ab"
HEX32 = "0123456789abcdef0123456789abcdef"


# --------------------------------------------------------------------------- #
# normalize_segment
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "segment,expected",
    [
        ("42", ":id"),
        ("0", ":id"),
        ("007", ":id"),
        (UUID, ":uuid"),
        (UUID.upper(), ":uuid"),
        (HEX32, ":uuid"),
        ("deadbeef", "deadbeef"),       # 8 hex chars is NOT 32+ -> stays literal
        ("Users", "Users"),
        ("products", "products"),
        ("search", "search"),
        ("v1", "v1"),                   # has a digit but not all-numeric -> literal
        ("2fa", "2fa"),
    ],
)
def test_normalize_segment(segment, expected):
    assert normalize_segment(segment) == expected


# --------------------------------------------------------------------------- #
# normalize_path
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/Users/42", "/api/Users/:id"),
        ("/api/Users/42/Reviews/7", "/api/Users/:id/Reviews/:id"),
        (f"/api/Users/{UUID}", "/api/Users/:uuid"),
        (f"/rest/basket/{HEX32}", "/rest/basket/:uuid"),
        ("/rest/products/search", "/rest/products/search"),
        ("/api/Users/", "/api/Users"),        # trailing slash dropped
        ("/api//Users", "/api/Users"),         # duplicate slash collapsed
        ("/", "/"),                            # root preserved
        ("", "/"),                             # empty -> root
        ("/%32%34", "/%32%34"),                # percent-encoded stays literal
    ],
)
def test_normalize_path(path, expected):
    assert normalize_path(path) == expected


def test_trailing_slash_equivalence():
    assert normalize_path("/api/Users/") == normalize_path("/api/Users")


# --------------------------------------------------------------------------- #
# extract_param_names
# --------------------------------------------------------------------------- #
def test_query_keys_only():
    assert extract_param_names("sort=name&page=2") == {"sort", "page"}


def test_no_params_is_empty():
    assert extract_param_names() == set()
    assert extract_param_names("", None, None) == set()


def test_duplicate_query_names_collapse():
    assert extract_param_names("id=1&id=2&id=3") == {"id"}


def test_blank_value_query_kept():
    assert extract_param_names("q=") == {"q"}


def test_json_top_level_keys():
    body = '{"email": "a@b.c", "password": "x"}'
    assert extract_param_names(None, body, "application/json") == {"email", "password"}


def test_json_with_charset_content_type():
    body = '{"token": "x"}'
    assert extract_param_names(None, body, "application/json; charset=utf-8") == {"token"}


def test_json_bytes_body():
    body = b'{"email": "a@b.c"}'
    assert extract_param_names(None, body, "application/json") == {"email"}


def test_malformed_json_does_not_crash():
    assert extract_param_names("a=1", "{not valid json", "application/json") == {"a"}


def test_non_dict_json_contributes_nothing():
    assert extract_param_names(None, "[1, 2, 3]", "application/json") == set()
    assert extract_param_names(None, '"scalar"', "application/json") == set()


def test_nested_json_only_top_level_and_no_crash():
    body = '{"user": {"email": "a@b.c"}, "remember": true}'
    assert extract_param_names(None, body, "application/json") == {"user", "remember"}


def test_form_encoded_field_names():
    body = "email=a%40b.c&password=x"
    assert extract_param_names(None, body, "application/x-www-form-urlencoded") == {
        "email",
        "password",
    }


def test_multipart_field_names():
    body = (
        '------X\r\nContent-Disposition: form-data; name="file"; filename="a.png"\r\n\r\n'
        '...\r\n------X\r\nContent-Disposition: form-data; name="caption"\r\n\r\nhi\r\n------X--'
    )
    assert extract_param_names(None, body, "multipart/form-data; boundary=----X") == {
        "file",
        "caption",
    }


def test_unknown_content_type_ignores_body():
    assert extract_param_names("a=1", "<xml/>", "application/xml") == {"a"}


def test_query_and_body_merge():
    body = '{"password": "x"}'
    assert extract_param_names("redirect=/home", body, "application/json") == {
        "redirect",
        "password",
    }


# --------------------------------------------------------------------------- #
# signature
# --------------------------------------------------------------------------- #
def test_signature_basic():
    assert (
        signature("get", "http://localhost:3000/api/Users/42?sort=name")
        == "GET /api/Users/:id {sort}"
    )


def test_signature_method_uppercased():
    assert signature("post", "http://x/login").startswith("POST ")


def test_signature_no_params_has_empty_braces():
    assert signature("GET", "http://x/rest/products/search") == "GET /rest/products/search {}"


def test_signature_param_order_independent():
    a = signature("GET", "http://x/api/Users/1?sort=name&page=2")
    b = signature("GET", "http://x/api/Users/9?page=5&sort=email")
    assert a == b == "GET /api/Users/:id {page,sort}"


def test_signature_collapses_different_ids():
    a = signature("DELETE", "http://x/api/Users/42")
    b = signature("DELETE", "http://x/api/Users/99")
    assert a == b == "DELETE /api/Users/:id {}"


def test_signature_merges_query_and_body_params():
    sig = signature(
        "POST",
        "http://x/rest/user/login?return=/home",
        body='{"email": "a", "password": "b"}',
        content_type="application/json",
    )
    assert sig == "POST /rest/user/login {email,password,return}"
