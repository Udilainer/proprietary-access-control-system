from datetime import datetime, timezone
from typing import cast, Any

from rest_framework.request import Request
from django.http import HttpRequest
from rest_framework import exceptions, status
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from . import utils
from .models import (
    BlacklistedToken,
    BusinessObject,
    Permission,
    Role,
    User,
)
from .permissions import HasPermission, IsAuthenticatedOr401
from .serializers import (
    BusinessObjectSerializer,
    LoginSerializer,
    PermissionSerializer,
    RoleSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)

# --- Core Authentication Views ---


class RegisterView(APIView):
    """
    POST /auth/register/
    Регистрирует нового пользователя.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "User registered successfully."}, status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    """
    POST /auth/login/
    Авторизует пользователя и возвращает JWT токен.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        validated_data = serializer.validated_data
        if not isinstance(validated_data, dict):
            raise exceptions.ValidationError("Invalid validated data format.")
        user = validated_data.get("user")
        if not user:
            raise exceptions.AuthenticationFailed("Serializer did not return a user.")

        token = utils.generate_jwt(user)
        return Response({"token": token}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    POST /auth/logout/
    Выполняет выход текущего пользователя путем отзыва его JWT токена.
    """

    permission_classes = [IsAuthenticatedOr401]

    def post(self, request: HttpRequest) -> Response:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise exceptions.AuthenticationFailed(
                "Authorization header is missing or invalid."
            )

        token = auth_header.split(" ")[1]
        payload = utils.decode_jwt(token)
        if not payload:
            raise exceptions.AuthenticationFailed("Invalid token.")

        jti = payload["jti"]
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

        BlacklistedToken.objects.create(
            user=cast(User, request.user), jti=jti, expires_at=expires_at
        )

        return Response(
            {"message": "Successfully logged out."}, status=status.HTTP_200_OK
        )


# --- User Self-Service Views ---


class ProfileView(RetrieveUpdateAPIView):
    """
    GET /auth/profile/      – Получить профиль текущего пользователя.
    PUT /auth/profile/      – Обновить профиль текущего пользователя (имя/фамилия).
    PATCH /auth/profile/    – Частично обновить профиль текущего пользователя.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticatedOr401]

    def get_object(self) -> Any:
        return cast(User, self.request.user)


class DeleteAccountView(APIView):
    """
    POST /auth/delete-account/
    "Мягко" удаляет аккаунт текущего пользователя и отзывает его токен.
    """

    permission_classes = [IsAuthenticatedOr401]

    def post(self, request: HttpRequest) -> Response:
        user = cast(User, request.user)
        user.is_active = False
        user.save(update_fields=["is_active"])

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = utils.decode_jwt(token)
            if payload:
                expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                BlacklistedToken.objects.get_or_create(
                    user=user, jti=payload["jti"], defaults={"expires_at": expires_at}
                )

        return Response(
            {"message": "Account successfully marked for deletion."},
            status=status.HTTP_200_OK,
        )


# --- Admin CRUD ViewSets for RBAC Management ---


class RoleViewSet(ModelViewSet):
    """Админский CRUD для Ролей. Требует разрешения на бизнес-объект 'roles'."""

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticatedOr401, HasPermission]
    business_object_code = "roles"


class BusinessObjectViewSet(ModelViewSet):
    """Админский CRUD для Бизнес-Объектов. Требует разрешения 'business_objects'."""

    queryset = BusinessObject.objects.all()
    serializer_class = BusinessObjectSerializer
    permission_classes = [IsAuthenticatedOr401, HasPermission]
    business_object_code = "business_objects"


class PermissionViewSet(ModelViewSet):
    """Админский CRUD для Разрешений. Требует разрешения 'permissions'."""

    queryset = Permission.objects.all().select_related("role", "business_object")
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticatedOr401, HasPermission]
    business_object_code = "permissions"


# --- Mock Business Application Views ---


class ProductListView(APIView):
    """GET /products/ - Возвращает список моковых продуктов."""

    permission_classes = [IsAuthenticatedOr401, HasPermission]
    business_object_code = "products"
    required_action = "read_all"

    def get(self, request: HttpRequest) -> Response:
        data = [{"id": 1, "name": "Laptop"}, {"id": 2, "name": "Mouse"}]
        return Response(data, status=status.HTTP_200_OK)


class OrderListView(APIView):
    """GET /orders/ - Возвращает список моковых заказов."""

    permission_classes = [IsAuthenticatedOr401, HasPermission]
    business_object_code = "orders"
    required_action = "read_all"

    def get(self, request: HttpRequest) -> Response:
        data = [
            {"id": 101, "item": "Keyboard", "owner_id": 2},
            {"id": 102, "item": "Monitor", "owner_id": 3},
        ]
        return Response(data, status=status.HTTP_200_OK)
