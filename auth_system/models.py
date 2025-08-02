from __future__ import annotations
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """
    Кастомный менеджер модели пользователя, где электронная почта является
    уникальным идентификатором для аутентификации вместо имени пользователя.
    """

    def create_user(
        self, email: str, password: str | None = None, **extra_fields
    ) -> User:
        """
        Создает и сохраняет Пользователя с указанными электронной почтой и паролем.
        """
        if not email:
            raise ValueError(_("The Email must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self, email: str, password: str | None = None, **extra_fields
    ) -> User:
        """
        Создает и сохраняет Суперпользователя с указанными электронной почтой и паролем.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)


class Role(models.Model):
    """
    Представляет роли пользователей в системе, например,
    администратор, менеджер, пользователь.
    """

    name = models.CharField(
        _("Role Name"),
        max_length=100,
        unique=True,
        help_text=_("Name of the role, e.g., 'Administrator'")
    )

    class Meta:
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
        ordering = ["name"]

    def __str__(self):
        return self.name


class BusinessObject(models.Model):
    """
    Представляет ресурс или бизнес-сущность в системе, например, товары, заказы.
    """

    code = models.CharField(
        _("Object Code"),
        max_length=100,
        unique=True,
        help_text=_("A unique code, e.g., 'orders'")
    )
    name = models.CharField(
        _("Object Name"),
        max_length=255,
        help_text=_("Human readable name")
    )

    class Meta:
        verbose_name = _("Business Object")
        verbose_name_plural = _("Business Objects")
        ordering = ["name"]

    def __str__(self):
        return self.name


class User(AbstractBaseUser, PermissionsMixin):
    """
    Кастомная модель пользователя, поддерживающая
    электронную почту в качестве имени пользователя.
    """

    email = models.EmailField(_("Email Address"), unique=True)
    first_name = models.CharField(_("First Name"), max_length=150, blank=True)
    last_name = models.CharField(_("Last Name"), max_length=150, blank=True)

    role = models.ForeignKey(
        Role, on_delete=models.SET_NULL, null=True, blank=True, verbose_name=_("Role")
    )

    is_staff = models.BooleanField(_("staff status"), default=False)
    is_active = models.BooleanField(_("active"), default=True)
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def __str__(self):
        return self.email

    def get_full_name(self):
        """
        Возвращает имя плюс фамилию, с пробелом между ними.
        """
        full_name = "%s %s" % (self.first_name, self.last_name)
        return full_name.strip()


class Permission(models.Model):
    """
    Определяет права доступа для конкретной Роли к конкретному БизнесОбъекту.
    """

    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name=_("Role"))
    business_object = models.ForeignKey(
        BusinessObject, on_delete=models.CASCADE, verbose_name=_("Business Object")
    )

    can_create = models.BooleanField(_("Can Create"), default=False)
    can_read_own = models.BooleanField(_("Can Read Own"), default=False)
    can_read_all = models.BooleanField(_("Can Read All"), default=False)
    can_update_own = models.BooleanField(_("Can Update Own"), default=False)
    can_update_all = models.BooleanField(_("Can Update All"), default=False)
    can_delete_own = models.BooleanField(_("Can Delete Own"), default=False)
    can_delete_all = models.BooleanField(_("Can Delete All"), default=False)

    class Meta:
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")
        unique_together = ("role", "business_object")
        ordering = ["role__name", "business_object__name"]

    def __str__(self):
        return f"Permissions for {self.role.name} on {self.business_object.name}"


class BlacklistedToken(models.Model):
    """
    Хранит отозванные JWT для обработки выхода из системы.
    """

    jti = models.CharField(_("JWT ID"), max_length=255, unique=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="blacklisted_tokens",
        verbose_name=_("User"),
    )
    expires_at = models.DateTimeField(_("Expires At"))

    class Meta:
        verbose_name = _("Blacklisted Token")
        verbose_name_plural = _("Blacklisted Tokens")

    def __str__(self):
        return f"Blacklisted token for {self.user}"
