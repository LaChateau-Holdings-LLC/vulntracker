"""OIDC configuration, token validation and server-side sessions."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


class AuthError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_url(value):
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError("OIDC configuration and provider endpoints must use HTTPS.")
    return url


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def provider_json(url, values=None, headers=None):
    https_url(url)
    body = urlencode(values).encode() if values else None
    request = Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    with build_opener(NoRedirects()).open(request, timeout=8) as response:
        content = response.read(1_000_001)
    if len(content) > 1_000_000:
        raise AuthError("The provider response was too large.")
    result = json.loads(content)
    if not isinstance(result, dict):
        raise AuthError("The provider returned an invalid response.")
    return result


@dataclass(frozen=True)
class OIDC:
    mode: str = "off"
    provider_name: str = "OpenID Connect"
    issuer: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    redirect_uri: str = ""
    scopes: str = "openid profile email"
    claim: str = "groups"
    allowed_value: str = ""
    admin_value: str = ""
    token_auth: str = ""

    @classmethod
    def from_env(cls):
        mode = os.getenv("TRACKER_AUTH_MODE", "off")
        if mode not in {"off", "test", "required"}:
            raise ValueError("TRACKER_AUTH_MODE must be off, test, or required.")
        if mode == "off":
            return cls()
        tenant = os.getenv("OIDC_ENTRA_TENANT_ID", "").strip()
        issuer = os.getenv("OIDC_ISSUER_URL", "").strip()
        if tenant:
            if issuer:
                raise ValueError("Configure either OIDC_ENTRA_TENANT_ID or OIDC_ISSUER_URL.")
            issuer = f"https://login.microsoftonline.com/{UUID(tenant)}/v2.0"
        if https_url(issuer).query:
            raise ValueError("OIDC_ISSUER_URL cannot include a query string.")
        redirect = os.getenv("OIDC_REDIRECT_URI", "").strip()
        url = https_url(redirect)
        if url.path != "/auth/callback" or url.query:
            raise ValueError("OIDC_REDIRECT_URI must end in /auth/callback.")
        client_id = os.getenv("OIDC_CLIENT_ID", "").strip()
        secret = os.getenv("OIDC_CLIENT_SECRET", "")
        if not client_id or not secret:
            raise ValueError("Set OIDC_CLIENT_ID and OIDC_CLIENT_SECRET.")
        auth = os.getenv("OIDC_TOKEN_AUTH_METHOD", "")
        if auth not in {"", "client_secret_basic", "client_secret_post"}:
            raise ValueError("OIDC_TOKEN_AUTH_METHOD must be client_secret_basic or client_secret_post.")
        scopes = os.getenv("OIDC_SCOPES", "openid profile email").split()
        if "openid" not in scopes:
            raise ValueError("OIDC_SCOPES must include openid.")
        return cls(mode, os.getenv("OIDC_PROVIDER_NAME", "") or ("Microsoft Entra ID" if tenant else "OpenID Connect"),
                   issuer, client_id, secret, redirect, " ".join(scopes),
                   os.getenv("OIDC_ACCESS_CLAIM", "") or ("roles" if tenant else "groups"),
                   os.getenv("OIDC_ALLOWED_VALUE", ""), os.getenv("OIDC_ADMIN_VALUE", ""), auth)

    @property
    def fingerprint(self):
        return digest(json.dumps((self.mode, self.issuer, self.client_id, self.client_secret,
                                  self.redirect_uri, self.scopes, self.claim, self.allowed_value,
                                  self.admin_value, self.token_auth)))

    def discovery(self):
        config = provider_json(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if config.get("issuer") != self.issuer:
            raise AuthError("The provider issuer does not match the configured issuer.")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(config.get(key), str):
                raise AuthError("The provider discovery document is missing an endpoint.")
            https_url(config[key])
        return config

    def start(self, db):
        config = self.discovery()
        state, binding, verifier, nonce = [secrets.token_urlsafe(32) for _ in range(4)]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        now = int(time.time())
        db.execute("DELETE FROM oidc_flows WHERE expires <= ?", (now,))
        db.execute("INSERT INTO oidc_flows VALUES (?, ?, ?, ?, ?, ?)",
                   (digest(state), digest(binding), verifier, nonce, self.fingerprint, now + 600))
        endpoint = config["authorization_endpoint"]
        url = endpoint + ("&" if urlsplit(endpoint).query else "?") + urlencode({
            "response_type": "code", "response_mode": "query", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": self.scopes, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        return url, binding

    def finish(self, flow, code):
        import jwt
        from urllib.parse import quote_plus

        config = self.discovery()
        methods = config.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
        method = self.token_auth or ("client_secret_basic" if "client_secret_basic" in methods else "client_secret_post")
        values = {"grant_type": "authorization_code", "code": code, "code_verifier": flow["verifier"],
                  "redirect_uri": self.redirect_uri}
        headers = {}
        if method == "client_secret_basic":
            credential = quote_plus(self.client_id) + ":" + quote_plus(self.client_secret)
            headers["Authorization"] = "Basic " + base64.b64encode(credential.encode()).decode()
        else:
            values.update(client_id=self.client_id, client_secret=self.client_secret)
        token = provider_json(config["token_endpoint"], values, headers).get("id_token")
        if not isinstance(token, str):
            raise AuthError("The provider did not return an ID token.")
        try:
            key_id = jwt.get_unverified_header(token).get("kid")
            keys = jwt.PyJWKSet.from_dict(provider_json(config["jwks_uri"])).keys
            signing_key = next((key for key in keys if key.key_id == key_id and key.algorithm_name == "RS256"
                                and key.public_key_use in (None, "sig")), None)
            if not signing_key:
                raise AuthError("The provider did not supply a matching RS256 signing key.")
            claims = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=self.client_id,
                                issuer=self.issuer, leeway=30,
                                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]})
        except jwt.PyJWTError as error:
            raise AuthError("The provider ID token could not be verified.") from error
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(nonce.encode(), flow["nonce"].encode()):
            raise AuthError("The sign-in response did not match the request.")
        audience = claims["aud"]
        if ("azp" in claims or (isinstance(audience, list) and len(audience) > 1)) and claims.get("azp") != self.client_id:
            raise AuthError("The ID token was issued to a different client.")
        memberships = claims.get(self.claim, [])
        if isinstance(memberships, str):
            memberships = [memberships]
        if not isinstance(memberships, list):
            memberships = []
        admin = not self.admin_value or self.admin_value in memberships
        if self.allowed_value and self.allowed_value not in memberships and not (
            self.admin_value and self.admin_value in memberships
        ):
            raise AuthError("This account is not assigned access to the tracker.")
        names = (claims.get("name"), claims.get("preferred_username"), claims.get("email"), claims["sub"])
        name = next((value[:200] for value in names if isinstance(value, str) and value), "Signed-in user")
        return name, admin

    def session(self, db, token):
        if not token:
            return None
        row = db.execute("""
            SELECT name, admin FROM oidc_sessions
            WHERE token = ? AND config = ? AND expires > ?
        """, (digest(token), self.fingerprint, int(time.time()))).fetchone()
        return dict(row) if row else None
