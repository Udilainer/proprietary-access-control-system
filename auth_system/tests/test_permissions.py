import pytest
from rest_framework import status
import allure

PERMISSION_TEST_CASES = [
    ("admin", "/api/auth/products/", status.HTTP_200_OK),
    ("admin", "/api/auth/orders/", status.HTTP_200_OK),
    ("admin", "/api/auth/roles/", status.HTTP_200_OK),

    ("manager", "/api/auth/products/", status.HTTP_200_OK),
    ("manager", "/api/auth/orders/", status.HTTP_200_OK),
    ("manager", "/api/auth/roles/", status.HTTP_403_FORBIDDEN),

    ("user", "/api/auth/products/", status.HTTP_403_FORBIDDEN),
    ("user", "/api/auth/orders/", status.HTTP_403_FORBIDDEN),
    ("user", "/api/auth/roles/", status.HTTP_403_FORBIDDEN),
]


@pytest.mark.django_db
@allure.feature("Authorization (RBAC)")
class TestPermissions:

    @pytest.mark.parametrize(
        "user_role, endpoint, expected_status", PERMISSION_TEST_CASES
    )
    @allure.story("Endpoint Access Control")
    def test_role_based_permissions(
        self, request, user_role, endpoint, expected_status
    ):
        """
        Тестирует матрицу разрешений для разных ролей в отношении различных эндпоинтов.
        """
        client = request.getfixturevalue(f"{user_role}_client")

        allure.dynamic.title(f"Тест доступа '{user_role}' к '{endpoint}'")

        response = client.get(endpoint)

        assert response.status_code == expected_status
