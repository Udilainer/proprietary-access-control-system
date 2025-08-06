from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import NotAuthenticated
from rest_framework import status
from rest_framework.response import Response


def exception_handler(exc, context):
    """
    Пользовательский обработчик исключений для DRF, возвращающий 401 для
    неаутентифицированных запросов.
    """

    if isinstance(exc, NotAuthenticated):
        response = Response({"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)
        response["WWW-Authenticate"] = 'Bearer realm="api"'
        return response

    return drf_exception_handler(exc, context)
