from typing import cast, Type
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

from auth_system.models import User as CustomUser
from auth_system.models import Role, BusinessObject, Permission

User: Type[CustomUser] = cast(Type[CustomUser], get_user_model())


class Command(BaseCommand):
    help = "Seed initial roles, business objects, permissions, and test users."

    TEST_EMAILS = {"admin@example.com", "manager@example.com", "user@example.com"}

    def handle(self, *args, **options):
        self.stdout.write("Clearing old data …")

        Permission.objects.all().delete()
        Role.objects.all().delete()
        BusinessObject.objects.all().delete()
        User.objects.filter(email__in=self.TEST_EMAILS).delete()

        roles = {
            "Admin": Role.objects.create(name="Admin"),
            "Manager": Role.objects.create(name="Manager"),
            "User": Role.objects.create(name="User"),
        }

        bos = {
            "users": BusinessObject.objects.create(code="users", name="Users"),
            "products": BusinessObject.objects.create(code="products", name="Products"),
            "orders": BusinessObject.objects.create(code="orders", name="Orders"),
        }

        def add_perm(role_key, bo_key, **flags):
            Permission.objects.create(
                role=roles[role_key], business_object=bos[bo_key], **flags
            )

        for bo_key in bos:
            add_perm(
                "Admin",
                bo_key,
                can_create=True,
                can_read_own=True,
                can_read_all=True,
                can_update_own=True,
                can_update_all=True,
                can_delete_own=True,
                can_delete_all=True,
            )

        for bo_key in ("products", "orders"):
            add_perm(
                "Manager",
                bo_key,
                can_create=True,
                can_read_own=True,
                can_read_all=True,
                can_update_own=True,
                can_update_all=False,
                can_delete_own=False,
                can_delete_all=False,
            )

        add_perm(
            "Manager",
            "users",
            can_create=False,
            can_read_own=False,
            can_read_all=True,
            can_update_own=False,
            can_update_all=False,
            can_delete_own=False,
            can_delete_all=False,
        )

        add_perm(
            "User",
            "users",
            can_create=False,
            can_read_own=True,
            can_read_all=False,
            can_update_own=True,
            can_update_all=False,
            can_delete_own=True,
            can_delete_all=False,
        )
        for bo_key in ("products", "orders"):
            add_perm("User", bo_key)

        users_to_seed = [
            {
                "first_name": "Admin",
                "last_name": "User",
                "email": "admin@example.com",
                "password": "Test123!",
                "role": roles["Admin"],
                "is_staff": True,
                "is_superuser": True,
            },
            {
                "first_name": "Manager",
                "last_name": "User",
                "email": "manager@example.com",
                "password": "Test123!",
                "role": roles["Manager"],
            },
            {
                "first_name": "Regular",
                "last_name": "User",
                "email": "user@example.com",
                "password": "Test123!",
                "role": roles["User"],
            },
        ]

        for data in users_to_seed:
            raw_pwd = data.pop("password")
            email = data["email"]

            user, created = User.objects.update_or_create(
                email=email,
                defaults=data,
            )
            if created:
                user.set_password(raw_pwd)
                user.save()
            else:
                if not user.check_password(raw_pwd):
                    user.set_password(raw_pwd)
                if user.role != data["role"]:
                    user.role = data["role"]
                user.save()

        self.stdout.write(self.style.SUCCESS("Seed completed successfully."))
