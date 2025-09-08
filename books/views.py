# books/views.py
from rest_framework import generics, permissions, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django_filters import rest_framework as django_filters
from .models import Book
from .serializers import BookSerializer, BookListSerializer
from .permissions import BookPermissions
from accounts.permissions import IsAdminUser
from rest_framework import status
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.openapi import OpenApiParameter
from drf_spectacular import openapi

@extend_schema(
    summary="Add a new book",
    description="Create a new book entry in the system",
    responses={201: BookSerializer}
)
class AddBookView(APIView):
    """
    View for adding new books to the system
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Create a serializer instance with the request data
        serializer = BookSerializer(data=request.data)
        
        if serializer.is_valid():
            # Set the added_by field to the current user
            serializer.save(added_by=request.user)
            
            return Response(
                {
                    'message': 'Book added successfully!',
                    'book': serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        
        return Response(
            {
                'message': 'Failed to add book',
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )

class BookFilter(django_filters.FilterSet):
    """Custom filter for books with more options"""
    title = django_filters.CharFilter(lookup_expr='icontains')
    author = django_filters.CharFilter(lookup_expr='icontains')
    publication_year = django_filters.NumberFilter(field_name='publication_date', lookup_expr='year')
    
    class Meta:
        model = Book
        fields = {
            'genre': ['exact'],
            'is_available': ['exact'],
            'publication_date': ['gte', 'lte'],
        }

@extend_schema_view(
    list=extend_schema(
        summary="List all books",
        description="Retrieve a list of all books with filtering and search capabilities",
        parameters=[
            OpenApiParameter(name='search', description='Search in title, author, description', required=False, type=str),
            OpenApiParameter(name='genre', description='Filter by genre', required=False, type=str),
            OpenApiParameter(name='is_available', description='Filter by availability', required=False, type=bool),
        ]
    ),
    create=extend_schema(
        summary="Create a new book",
        description="Add a new book to the collection (requires authentication)"
    )
)
class BookListView(generics.ListCreateAPIView):
    """
    List all books (public) and create new books (authenticated users only)
    
    This view provides:
    - GET: List all books with filtering and search
    - POST: Create new book (authenticated users only)
    """
    queryset = Book.objects.all()
    permission_classes = [BookPermissions]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_class = BookFilter
    search_fields = ['title', 'author', 'description']
    ordering_fields = ['title', 'author', 'date_added', 'publication_date']
    ordering = ['-date_added']  # Default ordering
    
    def get_serializer_class(self):
        if self.request.method == 'GET':
            return BookListSerializer
        return BookSerializer

class BookDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a book instance.
    
    Permissions:
    - Anyone can view (GET)
    - Book owner or admin can update (PUT/PATCH)
    - Only admin can delete (DELETE)
    """
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [BookPermissions]

@extend_schema(
    summary="Get my books",
    description="Retrieve books added by the authenticated user"
)
class MyBooksView(generics.ListAPIView):
    """
    List books added by the current authenticated user
    """
    serializer_class = BookListSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ['genre', 'is_available']
    search_fields = ['title', 'author']
    ordering_fields = ['title', 'date_added']
    
    def get_queryset(self):
        return Book.objects.filter(added_by=self.request.user)

class AdminBooksView(generics.ListAPIView):
    """
    Admin view of all books with additional management capabilities
    """
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_class = BookFilter
    search_fields = ['title', 'author', 'description']
    ordering_fields = ['title', 'author', 'date_added', 'added_by__email']
