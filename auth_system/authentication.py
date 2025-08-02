from rest_framework.authentication import BaseAuthentication
from .models import BlacklistedToken, User
from . import utils


class JWTAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith(f"{self.keyword} "):
            return None

        token = auth.split()[1]
        payload = utils.decode_jwt(token)
        if not payload:
            return None

        if BlacklistedToken.objects.filter(jti=payload.get("jti")).exists():
            return None

        try:
            user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            return None

        if not user.is_active:
            return None
        return (user, token)
