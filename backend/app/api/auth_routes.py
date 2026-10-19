from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, Any, List
from ..core.auth import hash_password, verify_password, create_access_token, get_current_user, require_roles
from ..core.audit import record_audit_entry
from ..db.database import connect, now_iso
from ..schemas import LoginRequest, UserCreate

router = APIRouter(prefix="/api/auth", tags=["Authentication & RBAC"])

@router.post("/login")
def login(body: LoginRequest):
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        if not user["active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated"
            )
            
        token_payload = {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
            "email": user["email"]
        }
        token = create_access_token(token_payload)
        
        record_audit_entry(
            db,
            actor=user["username"],
            action="USER_LOGIN",
            resource=f"user:{user['id']}",
            details={"ip": "127.0.0.1", "role": user["role"]}
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "full_name": user["full_name"],
                "email": user["email"]
            }
        }

@router.get("/me")
def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    return current_user

@router.get("/users")
def list_users(current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    with connect() as db:
        rows = db.execute("SELECT id, username, role, full_name, email, created_at, active FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]

@router.post("/register", status_code=201)
def register_user(body: UserCreate, current_user: Dict[str, Any] = Depends(require_roles(["admin"]))):
    with connect() as db:
        existing = db.execute("SELECT id FROM users WHERE username=?", (body.username,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered")
            
        now = now_iso()
        pwd_hash = hash_password(body.password)
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, full_name, email, created_at, active) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (body.username, pwd_hash, body.role, body.full_name, body.email, now)
        )
        
        record_audit_entry(
            db,
            actor=current_user.get("username", "admin"),
            action="USER_CREATED",
            resource=f"user:{cur.lastrowid}",
            details={"username": body.username, "role": body.role}
        )
        
        return {"id": cur.lastrowid, "username": body.username, "role": body.role, "message": "User account created"}
