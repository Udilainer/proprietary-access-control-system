from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import BasePermission

from .models import Permission, BusinessObject


class HasPermission(BasePermission):
    """
    Универсальная проверка разрешений на основе ролей (RBAC).

    Эта система позволяет декларативно определять необходимые разрешения
    для каждого представления, абстрагируя логику проверки прав доступа
    пользователя к определенным бизнес-объектам и действиям.

    Пример использования внутри представления:

        permission_classes = [HasPermission("products", "read_all")]

    Экземпляр класса инициализируется с использованием 'business_code'
    и 'action', что позволяет каждому представлению четко объявлять
    свои требования к доступу.
    """

    def __init__(self, business_code: str, action: str):
        """
        Инициализирует экземпляр класса HasPermission.

        Параметры:
            business_code (str): Уникальный код бизнес-объекта
                                 (например, "products", "orders").
            action (str): Действие, которое необходимо проверить
                          (например, "read_all", "create", "delete_own").
        """
        self.business_code = business_code
        self.action = action

    def _get_perm_record(self, user) -> Permission | None:
        """
        Получает запись разрешения для указанного пользователя и
        текущего бизнес-объекта.

        Параметры:
            user: Объект пользователя, для которого запрашивается разрешение.

        Возвращает:
            Permission | None: Объект разрешения, если найден, иначе None.
        """
        try:
            bo = BusinessObject.objects.get(code=self.business_code)
            return Permission.objects.get(role=user.role, business_object=bo)
        except ObjectDoesNotExist:
            return None

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        """
        Проверяет, имеет ли пользователь общие разрешения для доступа
        к представлению (например, 'read_all', 'create').

        Эта проверка выполняется для всех типов маршрутов (список и детали).
        Если пользователь является суперпользователем, доступ всегда разрешен.

        Параметры:
            request: Объект запроса Django.
            view: Объект представления Django REST Framework.

        Возвращает:
            bool: True, если пользователь имеет необходимое разрешение, иначе False.
        """
        user = request.user

        if getattr(user, "is_superuser", False):
            return True

        if not user or not user.is_authenticated:
            return False

        perm = self._get_perm_record(user)
        if not perm:
            return False

        return getattr(perm, f"can_{self.action}", False)

    def has_object_permission(  # type: ignore[override]
        self, request, view, obj
    ) -> bool:
        """
        Проверяет разрешения пользователя на доступ к конкретному экземпляру объекта.

        Эта проверка вызывается только для детальных маршрутов.

        Если действие предполагает доступ ко всем объектам (например, 'read_all'),
        тогда проверка has_permission() уже определила общий уровень доступа.
        Для действий типа *_own (например, 'update_own', 'delete_own')
        дополнительно проверяется, является ли пользователь владельцем объекта.

        Параметры:
            request: Объект запроса Django.
            view: Объект представления Django REST Framework.
            obj: Экземпляр объекта, к которому запрашивается доступ.

        Возвращает:
            bool: True, если пользователь имеет необходимое разрешение для
                  доступа к объекту, иначе False.
        """
        if self.has_permission(request, view):
            return True

        if not self.action.endswith("_own"):
            return False

        owner_id = getattr(obj, "owner_id", None)
        return owner_id == request.user.id
