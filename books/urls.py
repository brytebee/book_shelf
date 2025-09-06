# books/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.BookListView.as_view(), name='book_list'),
    path('<int:pk>/', views.BookDetailView.as_view(), name='book_detail'),
    path('my-books/', views.MyBooksView.as_view(), name='my_books'),
    path('admin/all-books/', views.AdminBooksView.as_view(), name='admin_books'),
    path('add/', views.AddBookView.as_view(), name='add_book'),
]
