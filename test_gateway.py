import unittest

from gateway import AccessDenied, AccessPolicy, Gateway, TokenSigner


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.signer = TokenSigner(b"s" * 32)
        self.gateway = Gateway(self.signer, AccessPolicy({("GET", "/v1/accounts"): "accounts:read"}), limit=2)
        self.now = 1000

    def headers(self, token, nonce="n-1", timestamp=None):
        return {
            "authorization": f"Bearer {token}",
            "x-request-timestamp": str(self.now if timestamp is None else timestamp),
            "x-request-nonce": nonce,
        }

    def test_valid_scoped_request_is_authorized(self):
        token = self.signer.issue("operator", ["accounts:read"], now=self.now)
        result = self.gateway.authorize("GET", "/v1/accounts", self.headers(token), self.now)
        self.assertEqual(result.subject, "operator")
        self.assertEqual(self.gateway.audit[-1]["decision"], "allow")

    def test_missing_scope_is_denied_and_audited(self):
        token = self.signer.issue("operator", ["accounts:write"], now=self.now)
        with self.assertRaises(AccessDenied):
            self.gateway.authorize("GET", "/v1/accounts", self.headers(token), self.now)
        self.assertEqual(self.gateway.audit[-1]["reason"], "insufficient_scope")

    def test_nonce_replay_is_denied(self):
        token = self.signer.issue("operator", ["accounts:read"], now=self.now)
        self.gateway.authorize("GET", "/v1/accounts", self.headers(token), self.now)
        with self.assertRaises(AccessDenied):
            self.gateway.authorize("GET", "/v1/accounts", self.headers(token), self.now)

    def test_unknown_route_is_denied(self):
        token = self.signer.issue("operator", ["accounts:read"], now=self.now)
        with self.assertRaises(AccessDenied):
            self.gateway.authorize("GET", "/admin", self.headers(token), self.now)


if __name__ == "__main__":
    unittest.main()
