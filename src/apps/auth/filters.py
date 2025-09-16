import django_filters
from django.db.models import Q

from src.apps.common.filters import BaseFilterSet
from .models import User, Role
from src.apps.auth.models import User

class UserFilter(BaseFilterSet):
    username = django_filters.CharFilter(field_name="username", lookup_expr="icontains")
    email = django_filters.CharFilter(field_name="email", lookup_expr="icontains")
    search = django_filters.CharFilter(method="filter_search",
                                       label="Search by username or email or phone number")
    role = django_filters.CharFilter(field_name="role", lookup_expr="iexact")

    def filter_search(self, queryset, name, value):
        if not value:
            return queryset
        
        return queryset.filter(
            Q(username__icontains=value) |
            Q(email__icontains=value) |
            Q(phone_number__icontains=value)
        )

    def filter_role(self, queryset, name, value):
        if not value:
            return queryset
        roles = value.split(",")
        return queryset.filter(role__in=roles)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'role', 'status', 'daterange', 'search']