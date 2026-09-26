"""Create an admin-only account without exposing public registration."""

from __future__ import annotations

import argparse
from getpass import getpass
from datetime import datetime, timezone

from pymongo.errors import DuplicateKeyError

from database import get_database, initialize_database
from security import hash_password


def create_admin(username: str, password: str) -> None:
    username = username.strip().lower()
    if len(username) < 3:
        raise ValueError("Username must contain at least 3 characters.")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    db = get_database()
    db.command("ping")
    initialize_database(db)
    try:
        db.admin_users.insert_one({
            "username": username,
            "password_hash": hash_password(password),
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
        })
    except DuplicateKeyError as error:
        raise ValueError("That administrator username already exists.") from error


def main() -> None:
    parser = argparse.ArgumentParser(description="KYC Watch administrator setup utility")
    parser.add_argument("command", choices=["create-admin"])
    parser.add_argument("--username", help="Admin login username")
    args = parser.parse_args()
    username = args.username or input("Admin username: ")
    password = getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        parser.error("Passwords do not match.")
    try:
        create_admin(username, password)
    except ValueError as error:
        parser.error(str(error))
    print(f"Administrator '{username.strip().lower()}' created.")


if __name__ == "__main__":
    main()
