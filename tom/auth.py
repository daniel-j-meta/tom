import asyncio
import hmac
import os
from pathlib import Path
from dataclasses import dataclass

import jwt
from aiohttp import web


@dataclass(frozen=True)
class Identity:
    email: str
    admin: bool = False


class Auth:
    def __init__(self, config):
        self.config = config
        self.issuer = f"https://{config.access_team}.cloudflareaccess.com"
        self.jwks = jwt.PyJWKClient(self.issuer + "/cdn-cgi/access/certs", timeout=10)
        token_path = Path(os.getenv("TOM_ADMIN_TOKEN_FILE", "/opt/tom/secrets/admin.token"))
        self.admin_token = token_path.read_text().strip() if token_path.exists() else ""

    def unix_admin(self, request):
        address = request.transport.get_extra_info("sockname") if request.transport else None
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return (
            isinstance(address, str)
            and address.endswith("/admin.sock")
            and bool(self.admin_token)
            and hmac.compare_digest(supplied, self.admin_token)
        )

    def verify_jwt(self, token):
        key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.config.access_aud,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        email = claims.get("email", "").lower()
        if email not in self.config.users:
            raise ValueError("User is not invited")
        return Identity(email, email == self.config.admin_email)

    async def identify(self, request):
        if self.unix_admin(request):
            return Identity(self.config.admin_email, True)
        if self.config.auth_mode == "local":
            supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
            supplied = supplied or request.cookies.get("tom_local", "")
            if hmac.compare_digest(supplied, self.config.local_token):
                return Identity(self.config.admin_email, True)
            raise web.HTTPUnauthorized(text="Sign in with the local development token")
        token = request.headers.get("Cf-Access-Jwt-Assertion", "")
        if not token:
            raise web.HTTPUnauthorized(text="Cloudflare Access authentication is required")
        try:
            return await asyncio.to_thread(self.verify_jwt, token)
        except (jwt.PyJWTError, ValueError, OSError):
            raise web.HTTPUnauthorized(
                text="Invalid or expired Cloudflare Access identity"
            ) from None

    def check_origin(self, request):
        if self.unix_admin(request):
            return
        # All browser mutations and WS upgrades are same-origin. CLI calls have a bearer token.
        if self.config.auth_mode == "local" and request.headers.get("Authorization"):
            return
        if request.headers.get("Origin") != self.config.public_origin:
            raise web.HTTPForbidden(text="A same-origin request is required")
