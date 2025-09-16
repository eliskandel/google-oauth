from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    UserRegisterView,
    UserLoginView,
    UserLogoutView,
    UserDetailsView,
    UserRetrieveView,
    UserListView,
    UserUpdateView,
    VerifyLoginOTPView,
    UserChangePasswordView,
    ForgotPasswordView,
    VerifyForgotPasswordView,
    ChangeForgotPasswordView,
    PermissionsListView,
    UserPermissionsView,
    # AddUserPermissionsView,
    UserDeleteView,
    GoogleAuthView
)

urlpatterns = [
    path("google/", GoogleAuthView.as_view(), name="google-auth-api"),
    path("register/", UserRegisterView.as_view(), name="user-register-api"),
    path("login/", UserLoginView.as_view(), name="user-login-api"),
    path(
        "token/refresh/", TokenRefreshView.as_view(), name="token-refresh-api-endpoint"
    ),
    path("logout/", UserLogoutView.as_view(), name="user-logout-api"),
    path("details/", UserDetailsView.as_view(), name="user-details-api"),
    path("retrieve/<uuid:pk>/", UserRetrieveView.as_view(), name="user-retrieve-api"),
    path("list/", UserListView.as_view(), name="user-list-api"),
    path("update/<uuid:pk>/", UserUpdateView.as_view(), name="user-update-api"),
    path("verify/login/otp/", VerifyLoginOTPView.as_view(), name="user-verify-api"),
    path(
        "change/password/",
        UserChangePasswordView.as_view(),
        name="user-change-password-api",
    ),
    path(
        "forgot/password/",
        ForgotPasswordView.as_view(),
        name="user-forgot-password-api",
    ),
    path(
        "verify/forgot/password/otp/",
        VerifyForgotPasswordView.as_view(),
        name="forgot-password-verify-api",
    ),
    path(
        "change/forgot/password/",
        ChangeForgotPasswordView.as_view(),
        name="user-change-forgot-password-api",
    ),
    path("permissions/", PermissionsListView.as_view(), name="permissions-list-api"),
    path(
        "permissions/user/<uuid:pk>/",
        UserPermissionsView.as_view(),
        name="user-permissions-api",
    ),
    # path(
    #     "permissions/add/",
    #     AddUserPermissionsView.as_view(),
    #     name="add-user-permissions-api",
    # ),
    path(
        "delete/<uuid:pk>/",
        UserDeleteView.as_view(),
        name="user-delete-api",
    ),
]