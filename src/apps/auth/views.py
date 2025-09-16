from django.utils import timezone
from rest_framework import generics, status, exceptions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Permission
from django.utils.crypto import get_random_string

from .serializers import (
    UserRegisterSerializer,
    UserLoginSerializer,
    UserLogoutSerializer,
    VerifyLoginOTPSerializer,
    UserSerializer,
    UserChangePasswordSerializer,
    ForgotPasswordSerializer,
    VerifyForgotPasswordSerializer,
    ChangeForgotPasswordSerializer,
    # AddUserPermissionsSerializer,
    PermissionsSerializer,
    UserDetailSerializer,
)
from .permissions import IsSuperAdminOrAdmin, IsSelfOrAdmin
from .models import User, Role
from src.apps.common.otp import OTPhandlers, OTPAction
from src.apps.auth.filters import UserFilter
from src.apps.common.tasks import send_user_mail



# users/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests

User = get_user_model()

class GoogleAuthView(APIView):
    
    def post(self, request):
        id_token_from_frontend = request.data.get('id_token')

        if not id_token_from_frontend:
            return Response({"error": "ID token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Verify the token
            idinfo = google_id_token.verify_oauth2_token(
                id_token_from_frontend,
                requests.Request(),
                "321288170457-gkiml23cbv686i94rcg544qom133oila.apps.googleusercontent.com"  # replace with your Google client ID
            )
        except ValueError:
            return Response({"error": "Invalid ID token"}, status=status.HTTP_400_BAD_REQUEST)

        # Get user info
        email = idinfo.get('email')
        name = idinfo.get('name')

        # Get or create the user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={'username': email.split('@')[0], 'first_name': name}
        )

        # Generate JWT
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username
            }
        })


class UserRegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):

        if request.data.get("role") in [Role.CLIENT, Role.STAFF, Role.ADMIN]:
            request.data["password"] = get_random_string(
                length=8,
                allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)

        if request.data.get("role") in [Role.CLIENT, Role.STAFF, Role.ADMIN]:
            send_user_mail.delay(
                subject="Welcome to Our Platform",
                recipients=[serializer.data["email"]],
                message=f"Hello {serializer.data['first_name']},\n\n"
                f"Your account has been created successfully. \n\n"
                f"Your temporary Username: {serializer.data['username']}\n\n Your Temporary Password: {request.data['password']}\n"
                f"Please log in and change your password.\n\n"
                f"Thank you for joining us!\n\n"
                f"Best regards,\n"
                f"The Team",
            )

        return Response(
            {"msg": "User registration successful"},
            status=status.HTTP_201_CREATED,
            headers=headers,
        )


class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user", None)

        # if user.email_verified:
        user.is_active = True
        user.last_login = timezone.now()
        user.save()

        token = TokenObtainPairSerializer.get_token(user)

        return Response(
            {
                "refresh": str(token),
                "access": str(token.access_token),
                "role": user.role,
                "msg": "User logged in successful",
                "details": UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )
        # else:
        #     otp_handler = OTPhandlers(request, user, OTPAction.LOGIN)
        #     otp_handler.send_otp()
        #     return Response({'msg': 'Login OTP has been sent to your email address'}, status=status.HTTP_200_OK)


class VerifyLoginOTPView(generics.GenericAPIView):
    serializer_class = VerifyLoginOTPSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user", None)

        if user is not None:
            token = TokenObtainPairSerializer.get_token(user)
            user.is_active = True
            user.last_login = timezone.now()
            user.save()

            return Response(
                {
                    "refresh": str(token),
                    "access": str(token.access_token),
                    "msg": "OTP verified successfully",
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"msg": "OTP verification failed"}, status=status.HTTP_400_BAD_REQUEST
        )


class UserLogoutView(generics.GenericAPIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        refresh_token = serializer.validated_data.get("refresh")
        if refresh_token is None:
            raise exceptions.APIException(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = RefreshToken(refresh_token)
        try:
            token.blacklist()
            user = request.user
            user.status = False
            user.save()
            return Response(
                {"msg": "User logged out successful"}, status=status.HTTP_200_OK
            )

        except Exception as e:
            raise exceptions.APIException(
                {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )


class UserRetrieveView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        id = self.kwargs.get("pk", None)
        try:
            return User.objects.get(id=id)
        except User.DoesNotExist:
            raise exceptions.APIException({"error": "User does not exist"})

    def get_queryset(self):
        return User.objects.all()


class UserDetailsView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get_queryset(self):
        return User.objects.all()


class UserListView(generics.ListAPIView):
    # permission_classes = [IsSuperAdminOrAdmin]
    serializer_class = UserDetailSerializer
    filterset_class = UserFilter

    def get_queryset(self):
        return User.objects.all()


class UserUpdateView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    lookup_field = "pk"

    def get_object(self):
        pk = self.kwargs.get("pk", None)
        if pk is not None:
            try:
                return User.objects.get(id=pk)
            except User.DoesNotExist:
                raise exceptions.APIException({"error": "User does not exist"})
        else:
            raise exceptions.APIException({"error": "User ID is required"})

    def get_queryset(self):
        return User.objects.all()


class UserChangePasswordView(generics.GenericAPIView):
    permission_classes = [IsSelfOrAdmin]
    serializer_class = UserChangePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user", None)

        if user is not None:
            token = TokenObtainPairSerializer.get_token(user)
            return Response(
                {
                    "refresh": str(token),
                    "access": str(token.access_token),
                    "msg": "Password changed successfully",
                },
                status=status.HTTP_200_OK,
            )

        return Response({"msg": "Password not changed"}, status=status.HTTP_200_OK)


class ForgotPasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user", None)

        if user is not None:
            otp_handler = OTPhandlers(request, user, OTPAction.RESET)
            otp_handler.send_otp()
            return Response(
                {"msg": "Reset OTP has been sent to your email address"},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"msg": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST
        )


class VerifyForgotPasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = VerifyForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = serializer.validated_data.get("message", None)
        return Response({"msg": message}, status=status.HTTP_200_OK)


class ChangeForgotPasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = ChangeForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user", None)

        if user is not None:
            token = TokenObtainPairSerializer.get_token(user)
            return Response(
                {
                    "refresh": str(token),
                    "access": str(token.access_token),
                    "msg": "Password changed successfully",
                },
                status=status.HTTP_200_OK,
            )

        return Response({"msg": "Password not changed"}, status=status.HTTP_200_OK)


class PermissionsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PermissionsSerializer

    def get_queryset(self):
        return Permission.objects.all()




class UserPermissionsView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PermissionsSerializer

    def get_queryset(self):
        user_id = self.kwargs.get("pk", None)
        try:
            user = User.objects.get(id=user_id)
            return user.user_permissions.all()
        except User.DoesNotExist:
            raise exceptions.APIException({"error": "User does not exist"})


class UserDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):

        if not self.request.user.is_superuser:
            raise exceptions.PermissionDenied(
                {"error": "You do not have permission to delete users"}
            )

        user_id = self.kwargs.get("pk", None)

        try:
            user = User.objects.get(id=user_id)

            if user.is_superuser:
                raise exceptions.PermissionDenied({"error": "Cannot delete superuser"})
            
            return user

        except User.DoesNotExist:
            raise exceptions.NotFound({"error": "User does not exist"})