from django.core.exceptions import ObjectDoesNotExist
from rest_framework import exceptions
from rest_framework.permissions import BasePermission

from .models import BusinessObject, Permission


class IsAuthenticatedOr401(BasePermission):
    """
    Разрешает доступ только аутентифицированным пользователям.
    Если пользователь не аутентифицирован, это вызывает исключение AuthenticationFailed,
    которое DRF преобразует в ответ с кодом 401 Unauthorized.
    """

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return True
        raise exceptions.NotAuthenticated(
            "Authentication credentials were not provided. "
            "Please include a valid Authorization header."
        )


class HasPermission(BasePermission):
    """
    Динамический класс разрешений на основе ролей, который проверяет права
    пользователя в отношении бизнес-объекта и конкретного выполняемого действия
    (например, просмотр списка, создание).

    Для использования добавьте следующее в ваш ViewSet или APIView:
        permission_classes = [HasPermission]
        business_object_code = "your_object_code"

    Для APIView, не являющихся ViewSet'ами, вы также должны указать действие:
        required_action = "read_all"
    """

    ACTION_MAP = {
        "list": "read_all",
        "create": "create",
        "retrieve": "read_own",
        "update": "update_own",
        "partial_update": "update_own",
        "destroy": "delete_own",
    }

    ALL_ACTION_MAP = {
        "read_own": "read_all",
        "update_own": "update_all",
        "delete_own": "delete_all",
    }

    def _get_perm_record(self, user, view):
        """
        Получает запись о разрешении для пользователя
        на основе конфигурации представления.
        """
        try:
            business_code = getattr(view, "business_object_code")
            bo = BusinessObject.objects.get(code=business_code)
            return Permission.objects.get(role=user.role, business_object=bo)
        except (ObjectDoesNotExist, AttributeError):
            return None

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        """
        Проверяет глобальные разрешения для представления
        (например, возможность просматривать список или создавать).
        """
        print(f">>> DEBUG: User type: {type(request.user)}")
        print(">>> DEBUG: HasPermission is running!")
        user = request.user

        if getattr(user, "is_superuser", False):
            return True

        if not user or not user.is_authenticated:
            return False

        perm_record = self._get_perm_record(user, view)
        if not perm_record:
            return False

        if hasattr(view, "required_action"):
            action = view.required_action
        else:
            action = self.ACTION_MAP.get(view.action)

        if not action:
            return False

        if action in ["create", "read_all"]:
            return getattr(perm_record, f"can_{action}", False)

        has_own_perm = getattr(perm_record, f"can_{action}", False)
        all_action = self.ALL_ACTION_MAP.get(action)
        has_all_perm = (
            getattr(perm_record, f"can_{all_action}", False) if all_action else False
        )

        return has_own_perm or has_all_perm

    def has_object_permission(  # type: ignore[override]
        self, request, view, obj
    ) -> bool:
        """
        Проверяет, имеет ли пользователь разрешение на
        выполнение действия над конкретным объектом.
        """
        user = request.user

        if getattr(user, "is_superuser", False):
            return True

        perm_record = self._get_perm_record(user, view)
        if not perm_record:
            return False

        action = self.ACTION_MAP.get(view.action)
        if not action:
            return False

        all_action = self.ALL_ACTION_MAP.get(action)
        if all_action and getattr(perm_record, f"can_{all_action}", False):
            return True

        if getattr(perm_record, f"can_{action}", False):
            if hasattr(obj, "owner_id"):
                return obj.owner_id == user.id
            return False

        return False
