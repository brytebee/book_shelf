# api/v1/views.py
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse

@api_view(['GET'])
def api_root(request, format=None):
    """
    API Root - provides links to all available endpoints
    """
    return Response({
        'books': reverse('book_list', request=request, format=format),
        'my_books': reverse('my_books', request=request, format=format),
        'auth': {
            'register': reverse('register', request=request, format=format),
            'login': reverse('login', request=request, format=format),
            'profile': reverse('profile', request=request, format=format),
            'refresh_token': reverse('token_refresh', request=request, format=format),
        },
        'admin': {
            'users': reverse('admin_users', request=request, format=format),
            'all_books': reverse('admin_books', request=request, format=format),
        }
    })