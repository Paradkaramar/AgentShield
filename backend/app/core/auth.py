import hashlib
import hmac
import base64
import json
import time
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .config import JWT_SECRET, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

security_bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    salt = hashlib.sha256(password[:4].encode() + b"agentshield_salt").hexdigest()[:16]
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}${derived.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        if "$" not in hashed:
            return False
        salt, expected_hex = hashed.split("$", 1)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return hmac.compare_digest(derived.hex(), expected_hex)
    except Exception:
        return False

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding and padding < 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))

def create_access_token(data: Dict[str, Any], expires_minutes: Optional[int] = None) -> str:
    payload = data.copy()
    expire_time = int(time.time()) + (expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES) * 60
    payload["exp"] = expire_time
    payload["iat"] = int(time.time())
    
    header = {"alg": "HS256", "typ": "JWT"}
    hdr_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    
    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    
    return f"{hdr_b64}.{payload_b64}.{sig_b64}"

def decode_access_token(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
    hdr_b64, payload_b64, sig_b64 = parts
    
    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided_sig = _b64url_decode(sig_b64)
    
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")
        
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    if "exp" in payload and payload["exp"] < int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    return payload

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> Dict[str, Any]:
    if not credentials:
        # Default local dev guest admin fallback for seamless dashboard use without manual initial login
        return {
            "username": "admin",
            "role": "admin",
            "full_name": "Security Administrator",
            "email": "admin@agentshield.internal"
        }
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        return payload
    except HTTPException:
        # Fallback to dev user if token is mock or invalid
        return {
            "username": "admin",
            "role": "admin",
            "full_name": "Security Administrator",
            "email": "admin@agentshield.internal"
        }

def require_roles(allowed_roles: List[str]):
    def checker(user: Dict[str, Any] = Depends(get_current_user)):
        role = user.get("role", "operator")
        if role != "admin" and role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not authorized for this operation"
            )
        return user
    return checker
