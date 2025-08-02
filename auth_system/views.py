from datetime import datetime, timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated

from . import serializers
from . import utils
from .models import BlacklistedToken, User


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "User registered successfully."}, status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.LoginSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        assert isinstance(serializer.validated_data, dict)
        user = serializer.validated_data.get("user")
        assert isinstance(user, User)

        token = utils.generate_jwt(user)
        return Response({"token": token}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                {"error": "Authorization header not found or invalid."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        token = auth_header.split(" ")[1]
        payload = utils.decode_jwt(token)

        if not payload or "jti" not in payload or "exp" not in payload:
            return Response(
                {"error": "Invalid token or missing claims."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        jti = payload["jti"]
        exp_timestamp = payload["exp"]
        expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

        BlacklistedToken.objects.create(
            user=request.user, jti=jti, expires_at=expires_at
        )

        return Response(
            {"message": "Successfully logged out."}, status=status.HTTP_200_OK
        )
