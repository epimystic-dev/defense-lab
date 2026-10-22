"""Parser-level tests."""

from __future__ import annotations

import json
import unittest

from headerscheck.parse import (
    load,
    parse_cookie_attributes,
    parse_hsts_directives,
)


class HttpTextTests(unittest.TestCase):
    def test_minimal_response_parses(self):
        text = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            "\r\n"
            "<html></html>\n"
        )
        responses, err = load(text)
        self.assertIsNone(err)
        self.assertEqual(len(responses), 1)
        r = responses[0]
        self.assertEqual(r.status, 200)
        self.assertEqual(r.get("content-type"), "text/html")
        self.assertTrue(r.has("Strict-Transport-Security"))

    def test_headers_only_file_parses(self):
        text = (
            "content-type: text/html\n"
            "strict-transport-security: max-age=100\n"
        )
        responses, err = load(text)
        self.assertIsNone(err)
        self.assertEqual(len(responses), 1)
        self.assertTrue(responses[0].has("Strict-Transport-Security"))

    def test_multiple_set_cookie_preserved(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: a=1; Secure\n"
            "Set-Cookie: b=2; Secure; HttpOnly\n"
            "\n"
        )
        responses, _ = load(text)
        self.assertEqual(len(responses[0].get_all("set-cookie")), 2)

    def test_folded_continuation_is_joined(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "X-Long: part-one,\n"
            " part-two\n"
            "\n"
        )
        responses, _ = load(text)
        self.assertEqual(responses[0].get("X-Long"), "part-one, part-two")

    def test_empty_file_errors(self):
        responses, err = load("")
        self.assertEqual(responses, [])
        self.assertIsNotNone(err)

    def test_malformed_line_is_skipped_not_crashed(self):
        text = "HTTP/1.1 200 OK\nnotaheader\nContent-Type: text/html\n\n"
        responses, err = load(text)
        self.assertIsNone(err)
        self.assertEqual(responses[0].get("Content-Type"), "text/html")

    def test_leading_request_block_is_skipped(self):
        text = (
            "GET /foo HTTP/1.1\n"
            "Host: example.test\n"
            "\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/plain\n"
            "\n"
        )
        responses, err = load(text)
        self.assertIsNone(err)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].status, 200)


class JsonTests(unittest.TestCase):
    def test_har_entries_parse(self):
        doc = {
            "log": {"entries": [
                {
                    "request": {"url": "https://example.test/"},
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "text/html"},
                        ],
                    },
                },
            ]},
        }
        responses, err = load(json.dumps(doc))
        self.assertIsNone(err)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].scheme, "https")

    def test_single_entry_parses(self):
        doc = {
            "request": {"url": "http://example.test/"},
            "response": {
                "status": 403,
                "headers": [{"name": "X-K", "value": "v"}],
            },
        }
        responses, err = load(json.dumps(doc))
        self.assertIsNone(err)
        self.assertEqual(responses[0].scheme, "http")
        self.assertEqual(responses[0].status, 403)

    def test_headers_dict_blob(self):
        doc = {
            "url": "https://example.test/",
            "headers": {"Content-Type": "text/html"},
        }
        responses, err = load(json.dumps(doc))
        self.assertIsNone(err)
        self.assertEqual(responses[0].scheme, "https")
        self.assertEqual(responses[0].get("Content-Type"), "text/html")

    def test_bad_json_errors(self):
        responses, err = load("{not-json")
        self.assertEqual(responses, [])
        self.assertIsNotNone(err)


class HstsParseTests(unittest.TestCase):
    def test_basic(self):
        d = parse_hsts_directives(
            "max-age=31536000; includeSubDomains; preload"
        )
        self.assertEqual(d["max-age"], "31536000")
        self.assertTrue(d.get("includesubdomains"))
        self.assertTrue(d.get("preload"))

    def test_quotes_stripped(self):
        d = parse_hsts_directives('max-age="100"')
        self.assertEqual(d["max-age"], "100")


class CookieParseTests(unittest.TestCase):
    def test_name_value_recorded(self):
        d = parse_cookie_attributes("sid=abc; Path=/; Secure; HttpOnly")
        self.assertEqual(d["__name"], "sid")
        self.assertEqual(d["__value"], "abc")
        self.assertIn("secure", d)
        self.assertIn("httponly", d)
        self.assertEqual(d["path"], "/")

    def test_samesite_value(self):
        d = parse_cookie_attributes("sid=abc; SameSite=Lax")
        self.assertEqual(d["samesite"], "Lax")


if __name__ == "__main__":
    unittest.main()
