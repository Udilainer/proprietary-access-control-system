import uuid
from datetime import datetime, timedelta, timezone

import jwt
from django.conf import settings
from django.http import HttpRequest

from .models import User, BlacklistedToken


def generate_jwt(user: User) -> str:
    """
    Генерирует JWT для данного пользователя.
    """
    payload = {
        'user_id': user.pk,
        'role': user.role.name if user.role else None,
        'exp': datetime.now(timezone.utc) + timedelta(
            seconds=int(settings.JWT_LIFETIME_SECONDS)
        ),
        'iat': datetime.now(timezone.utc),
        'jti': str(uuid.uuid4()),
    }

    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
    return token


def decode_jwt(token: str) -> dict | None:
    """
    Декодирует JWT. Возвращает полезную нагрузку, если токен действителен, иначе None.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def blacklist_token(request: HttpRequest) -> bool:
    """
    Отзывает JWT-токен из заголовка Authorization в запросе.
    Возвращает True, если токен был успешно отозван, в противном случае — False.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False

    token = auth_header.split(" ")[1]
    payload = decode_jwt(token)
    if not payload:
        return False

    jti = payload["jti"]
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

    BlacklistedToken.objects.get_or_create(
        user=request.user, jti=jti, defaults={"expires_at": expires_at}
    )
    return True
