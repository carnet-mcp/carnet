"""Operator maintenance for the local identity provider.

    python -m carnet.localidp --state var/local --reset-password who@example.com

Password reset deliberately requires a shell on the machine that holds `accounts.db` —
the same reasoning as CLI role grants: shell access is the root of trust here, and an
email-based reset flow would need email infrastructure this mode does not have. The
front door (`carnet --local`) is the way to *run* the provider; this entry
point only maintains its accounts.
"""

import argparse
import getpass
import sys
from pathlib import Path

from . import accounts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state",
        default="var/local",
        help="the front door's state directory (default: var/local)",
    )
    parser.add_argument(
        "--reset-password",
        metavar="EMAIL",
        help="set a new password for an existing account, prompted twice",
    )
    args = parser.parse_args()

    if not args.reset_password:
        parser.error("nothing to do. --reset-password EMAIL is the one maintenance verb.")

    db_path = Path(args.state) / "accounts.db"
    if not db_path.exists():
        print(f"no accounts database at {db_path} - has the front door run?", file=sys.stderr)
        return 1

    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Again: "):
        print("they do not match; nothing changed.", file=sys.stderr)
        return 1

    db = accounts.open_db(str(db_path))
    try:
        accounts.set_password(db, args.reset_password, first)
    except accounts.AccountError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"password updated for {args.reset_password}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
