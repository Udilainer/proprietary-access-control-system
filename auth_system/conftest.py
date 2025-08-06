import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from . import utils

User = get_user_model()


@pytest.fixture
def api_client():
    """Фикстура для стандартного DRF API-клиента."""
    return APIClient()


@pytest.fixture(scope="session")
def django_db_setup(django_db_setup, django_db_blocker):
    """Загрузить начальные данные один раз за сессию тестирования."""
    with django_db_blocker.unblock():
        from django.core.management import call_command

        call_command("seed_data")


@pytest.fixture
def admin_user(db):
    """Фикстура для пользователя-администратора, созданного начальными данными."""
    return User.objects.get(email="admin@example.com")


@pytest.fixture
def manager_user(db):
    """Фикстура для пользователя-менеджера, созданного начальными данными."""
    return User.objects.get(email="manager@example.com")


@pytest.fixture
def user_user(db):
    """Фикстура для обычного пользователя, созданного начальными данными."""
    return User.objects.get(email="user@example.com")


def create_authenticated_client(user):
    """
    Вспомогательная функция для создания аутентифицированного
    клиента для данного пользователя.
    """
    token = utils.generate_jwt(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


@pytest.fixture
def admin_client(admin_user):
    """Аутентифицированный клиент для пользователя-администратора."""
    return create_authenticated_client(admin_user)


@pytest.fixture
def manager_client(manager_user):
    """Аутентифицированный клиент для пользователя-менеджера."""
    return create_authenticated_client(manager_user)


@pytest.fixture
def user_client(user_user):
    """Аутентифицированный клиент для обычного пользователя."""
    return create_authenticated_client(user_user)
