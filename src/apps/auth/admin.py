from django.contrib import admin
from .models import User
# Register your models here.

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "first_name", "last_name", "role", "is_active", "is_staff", "is_superuser", "date_joined")
    search_fields = ("username", "email", "first_name", "last_name")
    list_filter = ("role", "is_active", "is_staff", "is_superuser")
    ordering = ("-date_joined",)
    readonly_fields = ("date_joined", "last_login")