"""Server-side OIDC PKCE session store; browser only receives opaque cookies."""
from __future__ import annotations
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode, urlsplit
import httpx
import jwt
from fastapi import HTTPException

STATE_COOKIE = "__Host-np-oidc-state"
SESSION_COOKIE = "__Host-np-session"


class BrowserLogin:
    def __init__(self, redis_client, issuer, auth_url, token_url, client_id, public_origin):
        issuer_host = urlsplit(issuer)
        origin = urlsplit(public_origin)
        if (issuer_host.scheme != "https" or not issuer_host.hostname or
                origin.scheme != "https" or not origin.hostname or
                origin.path not in ("", "/") or origin.query or origin.fragment or not client_id):
            raise ValueError("Browser OIDC requires HTTPS issuer, origin and client ID")
        for url in (auth_url, token_url):
            u = urlsplit(url)
            if (u.scheme != "https" or u.netloc != issuer_host.netloc or
                    not u.path or u.query or u.fragment):
                raise ValueError("OIDC endpoints must use issuer HTTPS origin")
        self.redis = redis_client
        self.issuer = issuer.rstrip("/")
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        self.origin = public_origin.rstrip("/")
        self.callback = self.origin + "/auth/callback"

    def start(self):
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        saved = json.dumps({"verifier": verifier, "nonce": nonce})
        if not self.redis.set("np:oidc:state:" + state, saved, ex=300, nx=True):
            raise HTTPException(503, detail="Login cannot start")
        query = urlencode({
            "response_type": "code", "scope": "openid",
            "client_id": self.client_id, "redirect_uri": self.callback,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "nonce": nonce, "state": state,
        })
        return self.auth_url + "?" + query, state

    def consume(self, state, cookie):
        if (not cookie or len(state) > 128 or len(cookie) > 128 or
                not secrets.compare_digest(state, cookie)):
            raise HTTPException(401, detail="Invalid login state")
        data = self.redis.getdel("np:oidc:state:" + state)
        if not data:
            raise HTTPException(401, detail="Expired login state")
        return json.loads(data)

    async def exchange(self, code, pending, verifier):
        if not 8 <= len(code) <= 4096:
            raise HTTPException(401, detail="Invalid authorization code")
        try:
            async with httpx.AsyncClient(timeout=7, follow_redirects=False) as client:
                response = await client.post(self.token_url, data={
                    "grant_type": "authorization_code", "code": code,
                    "client_id": self.client_id, "redirect_uri": self.callback,
                    "code_verifier": pending["verifier"],
                })
            response.raise_for_status()
            if len(response.content) > 32768:
                raise ValueError("Oversized OIDC response")
            body = response.json()
            access, identity = body["access_token"], body["id_token"]
            if (body.get("token_type", "").lower() != "bearer" or
                    not isinstance(access, str) or not isinstance(identity, str)):
                raise ValueError("Invalid OIDC token response")
            principal = verifier.verify(access)
            key = verifier.jwks.get_signing_key_from_jwt(identity)
            claims = jwt.decode(
                identity, key.key, algorithms=["RS256"], audience=self.client_id,
                issuer=self.issuer, options={"require": ["iss", "aud", "sub", "iat", "exp"]},
                leeway=30,
            )
            if (claims.get("nonce") != pending["nonce"] or
                    claims["sub"] != principal.subject):
                raise ValueError("Invalid OIDC identity binding")
            access_claims = jwt.decode(access, options={"verify_signature": False})
            ttl = min(900, int(access_claims["exp"] - time.time() - 30))
            if ttl < 30:
                raise ValueError("OIDC token nearly expired")
            return access, ttl
        except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(401, detail="OIDC code exchange failed") from exc

    def create_session(self, token, ttl):
        sid = secrets.token_urlsafe(40)
        csrf = secrets.token_urlsafe(32)
        data = json.dumps({"token": token, "csrf": csrf})
        if not self.redis.set("np:oidc:session:" + sid, data, ex=ttl, nx=True):
            raise HTTPException(503, detail="Session creation failed")
        return sid

    def session(self, sid):
        if not sid or len(sid) > 128:
            return None
        data = self.redis.get("np:oidc:session:" + sid)
        return json.loads(data) if data else None

    def logout(self, sid):
        if sid and len(sid) <= 128:
            self.redis.delete("np:oidc:session:" + sid)
