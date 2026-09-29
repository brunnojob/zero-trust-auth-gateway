from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable


class AccessDenied(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    expires_at: int


class TokenSigner:
    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("signing secret must contain at least 32 bytes")
        self._secret = secret

    def issue(self, subject: str, scopes: Iterable[str], ttl_seconds: int = 300, now: int | None = None) -> str:
        issued = int(time.time()) if now is None else now
        if not subject or ttl_seconds < 1 or ttl_seconds > 900:
            raise ValueError("invalid token claims")
        claims = {
            "sub": subject,
            "scp": sorted(set(scopes)),
            "iat": issued,
            "exp": issued + ttl_seconds,
            "jti": secrets.token_urlsafe(18),
        }
        payload = self._encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signature = self._encode(hmac.new(self._secret, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def verify(self, token: str, now: int | None = None) -> Principal:
        parts = token.split(".")
        if len(parts) != 2:
            raise AccessDenied("invalid_token")
        payload, supplied = parts
        expected = self._encode(hmac.new(self._secret, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied, expected):
            raise AccessDenied("invalid_signature")
        try:
            claims = json.loads(self._decode(payload))
            current = int(time.time()) if now is None else now
            if claims["exp"] <= current or claims["iat"] > current + 30:
                raise AccessDenied("expired_token")
            if not claims["sub"] or not isinstance(claims["scp"], list):
                raise AccessDenied("invalid_claims")
            return Principal(claims["sub"], frozenset(claims["scp"]), claims["exp"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise AccessDenied("invalid_claims") from error

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int):
        if limit < 1 or window_seconds < 1:
            raise ValueError("rate-limit settings must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float) -> bool:
        events = self._events[key]
        boundary = now - self.window_seconds
        while events and events[0] <= boundary:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True


class NonceRegistry:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, int] = {}

    def claim(self, subject: str, nonce: str, now: int) -> bool:
        self._seen = {key: expires for key, expires in self._seen.items() if expires > now}
        identity = f"{subject}:{nonce}"
        if identity in self._seen or not nonce:
            return False
        self._seen[identity] = now + self.ttl_seconds
        return True


class AccessPolicy:
    def __init__(self, routes: dict[tuple[str, str], str]):
        self._routes = routes

    def required_scope(self, method: str, path: str) -> str:
        scope = self._routes.get((method.upper(), path))
        if scope is None:
            raise AccessDenied("route_not_allowed")
        return scope


class Gateway:
    def __init__(self, signer: TokenSigner, policy: AccessPolicy, limit: int = 60, window_seconds: int = 60, clock_skew_seconds: int = 30):
        self.signer = signer
        self.policy = policy
        self.limiter = SlidingWindowLimiter(limit, window_seconds)
        self.nonces = NonceRegistry()
        self.clock_skew_seconds = clock_skew_seconds
        self.audit: list[dict[str, str | int]] = []

    def authorize(self, method: str, path: str, headers: dict[str, str], now: int | None = None) -> Principal:
        current = int(time.time()) if now is None else now
        subject = "anonymous"
        try:
            authorization = headers.get("authorization", "")
            if not authorization.startswith("Bearer "):
                raise AccessDenied("missing_bearer_token")
            principal = self.signer.verify(authorization[7:], current)
            subject = principal.subject
            timestamp = int(headers.get("x-request-timestamp", ""))
            if abs(current - timestamp) > self.clock_skew_seconds:
                raise AccessDenied("stale_request")
            if not self.nonces.claim(subject, headers.get("x-request-nonce", ""), current):
                raise AccessDenied("replayed_request")
            scope = self.policy.required_scope(method, path)
            if scope not in principal.scopes:
                raise AccessDenied("insufficient_scope")
            if not self.limiter.allow(subject, current):
                raise AccessDenied("rate_limited")
            self._record(subject, method, path, "allow", "authorized", current)
            return principal
        except (AccessDenied, ValueError) as error:
            reason = str(error) or "invalid_request"
            self._record(subject, method, path, "deny", reason, current)
            raise AccessDenied(reason) from error

    def _record(self, subject: str, method: str, path: str, decision: str, reason: str, timestamp: int) -> None:
        self.audit.append({
            "subject": subject,
            "method": method.upper(),
            "path": path,
            "decision": decision,
            "reason": reason,
            "timestamp": timestamp,
        })


def main() -> None:
    secret = os.environ.get("GATEWAY_SECRET")
    if secret is None:
        print("Set GATEWAY_SECRET to a random secret of at least 32 bytes.")
        print("Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
        return
    signer = TokenSigner(secret.encode())
    gateway = Gateway(signer, AccessPolicy({("GET", "/v1/accounts"): "accounts:read"}))
    now = int(time.time())
    token = signer.issue("operator-17", ["accounts:read"], now=now)
    principal = gateway.authorize("GET", "/v1/accounts", {
        "authorization": f"Bearer {token}",
        "x-request-timestamp": str(now),
        "x-request-nonce": secrets.token_urlsafe(16),
    }, now)
    print(json.dumps({"authorized_subject": principal.subject, "audit": gateway.audit}, indent=2))


if __name__ == "__main__":
    main()
