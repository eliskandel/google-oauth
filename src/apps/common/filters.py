import django_filters

class BaseFilterSet(django_filters.FilterSet):
    status = django_filters.CharFilter(field_name="status", lookup_expr="iexact")
    daterange = django_filters.DateFromToRangeFilter(field_name="created_at")

    class Meta:
        abstract = True
        fields = ['status', 'daterange']