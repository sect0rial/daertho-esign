"""Admin commands.

    python -m esign.cli create-admin you@example.com        # prompts for a password
    python -m esign.cli reset-password you@example.com
"""
from __future__ import annotations

import getpass
import sys

from . import auth, store


def _pw() -> str:
    p = getpass.getpass("New password (10+ characters): ")
    if len(p) < 10 or p != getpass.getpass("Again: "):
        sys.exit("Passwords must match and be at least 10 characters.")
    return p


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) != 2 or argv[0] not in ("create-admin", "reset-password"):
        sys.exit(__doc__)
    cmd, email = argv[0], argv[1].strip().lower()
    s = store.open_store()
    u = s.get_user_by_email(email)
    if cmd == "create-admin":
        if u:
            sys.exit("That email already has an account.")
        s.create_user(email, "", "admin", auth.hash_pw(_pw()))
        print("Admin created:", email)
    else:
        if not u:
            sys.exit("No account with that email.")
        s.update_user(u["id"], pw_hash=auth.hash_pw(_pw()), session_ver=int(u["session_ver"]) + 1, disabled=0)
        print("Password reset; every session for", email, "was signed out.")


if __name__ == "__main__":
    main()
