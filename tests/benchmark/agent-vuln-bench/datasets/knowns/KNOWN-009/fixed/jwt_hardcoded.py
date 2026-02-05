"""Fixed: secret from environment."""
import os

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_TOKEN = os.environ.get("JWT_TOKEN", "")


def verify_token(token: str) -> bool:
    import jwt
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        return False
    jwt.decode(token, secret, algorithms=["HS256"])
    return True
