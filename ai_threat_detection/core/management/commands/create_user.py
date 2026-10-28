import getpass
import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.accounts.roles import ROLE_GROUPS, set_role
from ai_threat_detection.core.audit import audit


class Command(BaseCommand):
    help = "Create a local console user with a role (admin/analyst/viewer). Password is prompted, or read from an env var."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--role", required=True, choices=sorted(ROLE_GROUPS))
        parser.add_argument(
            "--password-env", help="name of an environment variable holding the password (non-interactive)"
        )

    def handle(self, *args, **o):
        user_model = get_user_model()
        if user_model.objects.filter(username=o["username"]).exists():
            raise CommandError("user exists")
        if o.get("password_env"):
            pw = os.environ.get(o["password_env"], "")
        else:
            pw = getpass.getpass("Password: ")
            if pw != getpass.getpass("Repeat: "):
                raise CommandError("passwords differ")
        user = user_model(username=o["username"])
        validate_password(pw, user)
        user.set_password(pw)
        user.save()
        set_role(user, o["role"])
        audit("cli", "user.create", "user", user.pk, "", role=o["role"])
        self.stdout.write(f"created {user.username} role={o['role']}")
