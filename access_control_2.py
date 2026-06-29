# ============================================================
#   Access Control Using Cryptography
#   Topic 28 - Security Functions of Cryptography
# ============================================================

import hashlib
import os
import datetime

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(text):
    print(f"\n{CYAN}{BOLD}{'='*55}")
    print(f"  {text}")
    print(f"{'='*55}{RESET}")

def ok(msg):   print(f"{GREEN}  [✔]  {msg}{RESET}")
def fail(msg): print(f"{RED}  [✘]  {msg}{RESET}")
def info(msg): print(f"{YELLOW}  [i]  {msg}{RESET}")

def hash_password(password: str, salt: bytes = None):
    """Hash a password with a random salt using SHA-256."""
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations=100_000
    )
    return salt, key

def verify_password(stored_salt, stored_hash, attempt: str) -> bool:
    """Return True only if the attempt matches the stored hash."""
    _, attempt_hash = hash_password(attempt, stored_salt)
    return attempt_hash == stored_hash

USER_DB: dict = {}

RESOURCES = {
    "admin":  ["View Reports", "Delete Users", "Manage Keys", "View Logs"],
    "user":   ["View Reports", "Update Profile"],
    "guest":  ["View Reports"],
}

def register(username: str, password: str, role: str = "user"):
    if username in USER_DB:
        fail(f"Username '{username}' already exists.")
        return
    salt, hashed = hash_password(password)
    USER_DB[username] = (salt, hashed, role)
    ok(f"Registered  →  user='{username}'  role='{role}'")
    info(f"Password is NEVER stored in plain text.")
    info(f"Stored hash (hex): {hashed.hex()[:32]}…")

def login(username: str, password: str):
    if username not in USER_DB:
        fail(f"Login failed: unknown user '{username}'.")
        return None
    salt, stored_hash, role = USER_DB[username]
    if verify_password(salt, stored_hash, password):
        ok(f"Login successful  →  Welcome, {username}!  (role: {role})")
        return role
    else:
        fail(f"Login failed: wrong password for '{username}'.")
        return None

def access_resource(username: str, role: str, resource: str):
    allowed = RESOURCES.get(role, [])
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if resource in allowed:
        ok(f"ACCESS GRANTED  →  '{username}' can '{resource}'   [{timestamp}]")
    else:
        fail(f"ACCESS DENIED   →  '{username}' cannot '{resource}'  [{timestamp}]")

def main():
    banner("STEP 1 – Registering Users")
    register("wafaa",   "Wafaa@2025",   role="admin")
    register("dowa",    "Dowa#2025",    role="user")
    register("tasneem", "Tasneem#2025", role="user")
    register("thekra",  "Thekra789",    role="guest")

    banner("STEP 2 – Stored Password Hashes  (not plain text!)")
    for name, (salt, hsh, role) in USER_DB.items():
        print(f"  {CYAN}{name:<10}{RESET}  role={role:<6}  "
              f"hash={hsh.hex()[:20]}…")

    banner("STEP 3 – Login Attempts")

    info("Wafaa logs in with CORRECT password:")
    wafaa_role = login("wafaa", "Wafaa@2025")

    print()
    info("Dowa logs in with WRONG password:")
    login("dowa", "wrongpass")

    print()
    info("Dowa logs in with CORRECT password:")
    dowa_role = login("dowa", "Dowa#2025")

    print()
    info("Unknown user tries to log in:")
    login("hacker", "hacker123")

    banner("STEP 4 – Role-Based Access Control (RBAC)")

    print(f"\n  {BOLD}Wafaa (admin) tries every resource:{RESET}")
    if wafaa_role:
        for res in ["View Reports", "Delete Users", "Manage Keys", "View Logs"]:
            access_resource("wafaa", wafaa_role, res)

    print(f"\n  {BOLD}Dowa (user) tries every resource:{RESET}")
    if dowa_role:
        for res in ["View Reports", "Delete Users", "Manage Keys", "Update Profile"]:
            access_resource("dowa", dowa_role, res)

    print(f"\n  {BOLD}Thekra (guest) tries every resource:{RESET}")
    thekra_role = login("thekra", "Thekra789")
    if thekra_role:
        for res in ["View Reports", "Delete Users", "Update Profile"]:
            access_resource("thekra", thekra_role, res)

    banner("SUMMARY – How Cryptography Enables Access Control")
    print(f"""
  {CYAN}1. Password Hashing{RESET}
     Passwords are hashed with SHA-256 + random salt.
     Even if the database is stolen, plain passwords stay secret.

  {CYAN}2. Salt{RESET}
     Each user gets a unique random salt, so two users
     with the same password will have different hashes.

  {CYAN}3. PBKDF2 (100,000 iterations){RESET}
     Slows down brute-force attacks dramatically.

  {CYAN}4. Role-Based Access Control (RBAC){RESET}
     After authentication, the role determines what
     resources the user is allowed to reach.

  {CYAN}5. Access Log with Timestamp{RESET}
     Every access attempt is recorded (GRANTED or DENIED).
""")

if __name__ == "__main__":
    main()
