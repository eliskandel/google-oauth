from rest_framework import serializers, exceptions
from src.apps.auth.models import User, Role
from django.contrib.auth.models import Permission
from django.db import transaction
from src.apps.common.otp import OTPhandlers, OTPAction
from src.apps.common.serializers import DynamicSerializer
from django.db.models import Q


class PermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = "__all__"


class UserRegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "username",
            "email",
            "password",
            "role",
            "phone_number",
        )

    def create(self, validated_data):
        first_name = validated_data.get("first_name", None)
        last_name = validated_data.get("last_name", None)
        username = validated_data.get("username", None)
        email = validated_data.get("email", None)
        password = validated_data.get("password", None)
        role = validated_data.get("role", Role.ADMIN)
        phone_number = validated_data.get("phone_number", None)
        with transaction.atomic():
            user: User = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password,
                phone_number=phone_number,
                role=role,
            )
        return user


class UserLoginSerializer(serializers.Serializer):

    username = serializers.CharField(max_length=255, required=True, allow_blank=False)
    password = serializers.CharField(max_length=255, required=True, allow_blank=False)

    def validate(self, attrs):
        username = attrs.get("username", None)
        password = attrs.get("password", None)

        if username is None or password is None:
            raise serializers.ValidationError({"msg": "Username or password missing"})

        try:
            user: User = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError({"msg": "Invalid username or password"})

        if user.check_password(password):
            attrs["user"] = user
        else:
            attrs["user"] = None
            raise serializers.ValidationError({"msg": "Invalid username or password"})

        return attrs


class VerifyLoginOTPSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True, allow_blank=False)
    otp = serializers.CharField(max_length=255, required=True, allow_blank=False)

    def validate(self, attrs):
        username = attrs.get("username", None)
        otp = attrs.get("otp", None)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            attrs["user"] = None
            raise exceptions.APIException("User does not exist")

        otp_handlers = OTPhandlers(
            request=self.context["request"],
            user=user,
            action=OTPAction.LOGIN,
        )

        verified, message = otp_handlers.verify_otp(otp)

        if not verified:
            raise serializers.ValidationError(message)

        attrs["user"] = user
        attrs["message"] = message

        return super().validate(attrs)


class UserLogoutSerializer(serializers.Serializer):

    refresh = serializers.CharField(
        max_length=255 * 2, required=True, allow_blank=False
    )


class UserSerializer(DynamicSerializer):
    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "username",
            "email",
            "image",
            "status",
            "role",
            "phone_number",
        )

    def update(self, instance: User, validated_data):
        for attr, value in validated_data.items():
            if attr == "image":
                if value is None:
                    instance.image = None  # type: ignore
                else:
                    instance.image = value
            else:
                setattr(instance, attr, value)

        instance.save()

        if instance.status == "inactive":
            instance.teams.clear()  # type: ignore

        return instance


class UserDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "username",
            "email",
            "image",
            "role",
            "phone_number",
            "status",
            "date_joined",
        )



class UserChangePasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True, allow_blank=False)
    old_password = serializers.CharField(
        max_length=255, required=True, allow_blank=False
    )
    new_password = serializers.CharField(
        max_length=255, required=True, allow_blank=False
    )

    def validate(self, attrs):
        username = attrs.get("username", None)
        old_password = attrs.get("old_password", None)
        new_password = attrs.get("new_password", None)

        if old_password is None or new_password is None:
            raise serializers.ValidationError(
                {"msg": "Old password or new password missing"}
            )

        try:
            user: User = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError({"msg": "Invalid username or password"})

        if not user.check_password(old_password):
            raise serializers.ValidationError({"msg": "Invalid username or password"})

        user.set_password(new_password)
        user.save()

        attrs["user"] = user

        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255, required=True, allow_blank=False)

    def validate(self, attrs):
        email = attrs.get("email", None)

        if email is None:
            raise serializers.ValidationError({"msg": "Email missing"})

        try:
            user: User = User.objects.get(email=email)
            attrs["user"] = user
        except User.DoesNotExist:
            attrs["user"] = None
            raise serializers.ValidationError({"msg": "Invalid username or password"})

        return attrs


class VerifyForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255, required=True, allow_blank=False)
    otp = serializers.CharField(max_length=255, required=True, allow_blank=False)

    def validate(self, attrs):
        email = attrs.get("email", None)
        otp = attrs.get("otp", None)

        try:
            user = User.objects.get(email=email)
            attrs["user"] = user
        except User.DoesNotExist:
            attrs["user"] = None
            raise exceptions.APIException("User does not exist")

        otp_handlers = OTPhandlers(
            request=self.context["request"],
            user=user,
            action=OTPAction.RESET,
        )
        verified, message = otp_handlers.verify_otp(otp)

        if not verified:
            raise serializers.ValidationError(message)

        attrs["message"] = message

        return super().validate(attrs)


class ChangeForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255, required=True, allow_blank=False)
    # username = serializers.CharField(max_length=255,required=True,allow_blank=False)
    # old_password = serializers.CharField(max_length=255,required=True,allow_blank=False)
    new_password = serializers.CharField(
        max_length=255, required=True, allow_blank=False
    )

    def validate(self, attrs):
        email = attrs.get("email", None)
        # old_password = attrs.get('old_password',None)
        new_password = attrs.get("new_password", None)

        # if old_password is None or new_password is None:
        #     raise serializers.ValidationError({'msg':'Old password or new password missing'})

        try:
            user: User = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"msg": "Invalid email or password"})

        # if not user.check_password(old_password):
        #     raise serializers.ValidationError({'msg':'Invalid username or password'})

        user.set_password(new_password)
        user.save()

        attrs["user"] = user

        return attrs


class AddUserPermissionsSerializer(serializers.Serializer):
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=255), required=True, allow_empty=False
    )

    def validate(self, attrs):
        permissions = attrs.get("permissions", None)

        if not permissions:
            raise serializers.ValidationError(
                {"msg": "Permissions list cannot be empty"}
            )

        for perm in permissions:
            if not isinstance(perm, str):
                raise serializers.ValidationError(
                    {"msg": f"Invalid permission: {perm}"}
                )

        return attrs