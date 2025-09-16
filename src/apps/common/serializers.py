from rest_framework.serializers import ModelSerializer

class DynamicSerializer(ModelSerializer):

    def __init__(self, *args, **kwargs):
        fields= kwargs.pop('fields', None)
        exclude = kwargs.pop('exclude', None)

        super().__init__(*args, **kwargs)

        if fields and fields != '__all__':
            for field in set(self.fields) - set(fields):
                self.fields.pop(field)
        
        if exclude:
            for field in set(exclude):
                self.fields.pop(field)

