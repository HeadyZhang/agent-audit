"""
JWT secret and token hardcoded.
Set C | ASI-05
"""
JWT_SECRET = "my-super-secret-key-do-not-share"  # LINE 5
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE2MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # LINE 6


def verify_token(token: str) -> bool:
    import jwt
    jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # uses hardcoded secret
    return True
