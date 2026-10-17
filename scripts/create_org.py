"""Create an organization and its first admin.

    python -m scripts.create_org --name "Snell Library" --timezone America/New_York \
        --admin-email admin@example.edu

Prompts for the admin password (or reads it from stdin with --password-stdin).
"""

import argparse
import getpass
import sys

from sqlmodel import Session

from app.config import get_settings
from app.db import make_engine
from app.models import Organization, Role, User
from app.schemas import OrgCreate
from app.security import hash_password


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--name", required=True)
    p.add_argument("--timezone", default="UTC", help="IANA name, e.g. America/New_York")
    p.add_argument("--admin-email", required=True)
    p.add_argument("--admin-name")
    p.add_argument("--password-stdin", action="store_true")
    args = p.parse_args()

    org_in = OrgCreate(name=args.name, timezone=args.timezone)
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Admin password: ")
        if password != getpass.getpass("Repeat: "):
            sys.exit("Passwords don't match.")
    if len(password) < 10:
        sys.exit("Use at least 10 characters.")

    engine = make_engine(get_settings().db_url)
    with Session(engine) as db:
        org = Organization(name=org_in.name, timezone=org_in.timezone)
        db.add(org)
        db.flush()
        admin = User(
            org_id=org.id,
            name=args.admin_name,
            email=args.admin_email.strip().lower(),
            role=Role.admin,
            password_hash=hash_password(password),
        )
        db.add(admin)
        db.commit()
        print(f"Created org {org.id} ({org.name}) with admin {admin.email} (user {admin.id}).")


if __name__ == "__main__":
    main()
