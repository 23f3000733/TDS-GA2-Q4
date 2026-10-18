import os

import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-ltr6egeb.apps.exam.local"

DEFAULT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----
"""

# Env override exists only so the service can be tested locally with a throwaway key.
PUBLIC_KEY = os.environ.get("IDP_PUBLIC_KEY", DEFAULT_PUBLIC_KEY)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def invalid() -> JSONResponse:
    return JSONResponse(status_code=401, content={"valid": False})


@app.get("/")
def health():
    return {"status": "ok"}


# Hardcoded stub: always reports ok/up. No Redis is actually checked.
@app.get("/healthz")
def healthz():
    return {"status": "ok", "redis": "up"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            return invalid()

        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],  # pin algorithm: blocks alg=none / HS256 confusion
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": AUDIENCE,
        }
    except Exception:
        return invalid()
