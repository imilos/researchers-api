#!/usr/bin/env python3
"""Simple CLI to fetch authorities for customers and update the database.

Usage:
  python scripts/fetch_authorities_cli.py

This imports `SessionLocal` and `fetch_and_update_authorities` from `app_fastapi`.
"""
from app_fastapi import SessionLocal, fetch_and_update_authorities


def main():
    db = SessionLocal()
    try:
        print("Starting continuous authorities fetcher (press Ctrl-C to stop)")
        fetch_and_update_authorities(db)
    except KeyboardInterrupt:
        print("Interrupted by user, exiting.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
