from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from .models import User, BlacklistedToken
from . import utils


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Пользовательское промежуточное ПО для аутентификации на основе JWT.
    """

    def process_request(self, request):
        request.user = AnonymousUser()
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return

        token = auth_header.split(" ")[1]
        payload = utils.decode_jwt(token)

        if not payload:
            return

        if BlacklistedToken.objects.filter(jti=payload.get("jti")).exists():
            return

        try:
            user = User.objects.get(id=payload.get("user_id"))
            if not user.is_active:
                return
            request.user = user
        except User.DoesNotExist:
            return
