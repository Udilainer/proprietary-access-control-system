from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("roles", views.RoleViewSet, basename="role")
router.register(
    "business-objects", views.BusinessObjectViewSet, basename="businessobject"
)
router.register("permissions", views.PermissionViewSet, basename="permission")

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("delete-account/", views.DeleteAccountView.as_view(), name="delete-account"),
    path("products/", views.ProductListView.as_view(), name="product-list"),
    path("orders/", views.OrderListView.as_view(), name="order-list"),
    path("", include(router.urls)),
]
