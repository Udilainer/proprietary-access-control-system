import uuid
from datetime import datetime, timedelta, timezone

import jwt
from django.conf import settings
from .models import User


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
