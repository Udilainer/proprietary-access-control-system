from typing import cast

from django.contrib.auth import authenticate
from rest_framework import serializers

from .models import User, CustomUserManager
from .models import Role, BusinessObject, Permission


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data: dict) -> User:
        validated_data.pop("password2")
        manager = cast(CustomUserManager, User.objects)
        return manager.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True,
    )

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        user = authenticate(
            request=self.context.get("request"), username=email, password=password
        )

        if not user:
            raise serializers.ValidationError(
                "Unable to log in with provided credentials.", code="authorization"
            )

        if not user.is_active:
            raise serializers.ValidationError(
                "User account is disabled.", code="authorization"
            )

        attrs["user"] = user
        return attrs


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "name"]


class BusinessObjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessObject
        fields = ["id", "code", "name"]


class PermissionSerializer(serializers.ModelSerializer):
    role = serializers.SlugRelatedField(slug_field="name", queryset=Role.objects.all())
    business_object = serializers.SlugRelatedField(
        slug_field="code", queryset=BusinessObject.objects.all()
    )

    class Meta:
        model = Permission
        fields = [
            "id",
            "role",
            "business_object",
            "can_create",
            "can_read_own",
            "can_read_all",
            "can_update_own",
            "can_update_all",
            "can_delete_own",
            "can_delete_all",
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name"]
        read_only_fields = ["id", "email"]
