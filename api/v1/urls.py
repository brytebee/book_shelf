# api/v1/urls.py
from django.urls import path, include
from .views import api_root

urlpatterns = [
    path('', api_root, name='api_root'),  # API root with links
    path('auth/', include('accounts.urls')),
    path('books/', include('books.urls')),
]
