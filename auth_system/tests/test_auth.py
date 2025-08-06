import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
import allure

User = get_user_model()


@pytest.mark.django_db
@allure.feature("Authentication")
class TestAuthentication:

    @allure.story("User Registration")
    @allure.title("Тест успешной регистрации пользователя")
    def test_user_registration_success(self, api_client):
        url = "/api/auth/register/"
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test.new.user@example.com",
            "password": "StrongPassword123!",
            "password2": "StrongPassword123!",
        }
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email=data["email"]).exists()

    @allure.story("User Login")
    @allure.title("Тест успешного входа пользователя в систему")
    def test_user_login_success(self, api_client, user_user):
        url = "/api/auth/login/"
        data = {"email": user_user.email, "password": "Test123!"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_200_OK
        assert "token" in response.data

    @allure.story("User Login")
    @allure.title("Тест неудачного входа с неверными учетными данными")
    def test_user_login_fail_bad_credentials(self, api_client, user_user):
        url = "/api/auth/login/"
        data = {"email": user_user.email, "password": "WrongPassword!"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @allure.story("User Logout")
    @allure.title("Тест успешного выхода из системы и отзыва токена")
    def test_user_logout_success(self, api_client, user_user):
        login_url = "/api/auth/login/"
        login_data = {"email": user_user.email, "password": "Test123!"}
        login_response = api_client.post(login_url, login_data)
        token = login_response.data["token"]

        logout_url = "/api/auth/logout/"
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        logout_response = api_client.post(logout_url)
        assert logout_response.status_code == status.HTTP_200_OK

        profile_url = "/api/auth/profile/"
        profile_response = api_client.get(profile_url)
        assert profile_response.status_code == status.HTTP_401_UNAUTHORIZED
