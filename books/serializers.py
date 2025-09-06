# books/serializers.py
from rest_framework import serializers
from .models import Book
from datetime import date

class BookSerializer(serializers.ModelSerializer):
    added_by_name = serializers.CharField(source='added_by.full_name', read_only=True)
    added_by_email = serializers.CharField(source='added_by.email', read_only=True)
    
    class Meta:
        model = Book
        fields = ('id', 'title', 'author', 'isbn', 'genre', 'publication_date', 
                 'description', 'page_count', 'added_by', 'added_by_name', 
                 'added_by_email', 'date_added', 'date_modified', 'is_available')
        read_only_fields = ('id', 'added_by', 'date_added', 'date_modified')
    
    # def create(self, validated_data):
    #     # Set the user who's adding the book
    #     validated_data['added_by'] = self.context['request'].user
    #     return super().create(validated_data)
    def create(self, validated_data):
        # The added_by field will be set by the view
        return Book.objects.create(**validated_data)

class BookListSerializer(serializers.ModelSerializer):
    """Simplified serializer for list views"""
    added_by_name = serializers.CharField(source='added_by.full_name', read_only=True)
    model_created_since = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Book
        fields = ('id', 'title', 'author', 'genre', 'added_by_name', 'date_added', 'is_available', 'model_created_since')

    def get_model_created_since(self, obj):
        time_diff = date.today() - obj.date_added.date()
        return time_diff.days