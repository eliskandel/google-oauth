from django.db import models
from src.apps.common.models import BaseModel
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.utils import timezone
from src.apps.common.utils import validate_image

# Create your models here.

class Role(models.TextChoices):
    ADMIN = "admin", "Admin"
    USER = "user", "User"
    STAFF = "staff", "Staff"


class UserManager(BaseUserManager):
    def create_user(self, username, email, password= None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        if not username:
            raise ValueError("Username is required")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
