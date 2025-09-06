# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'role', 'is_active', 'date_joined')
    list_filter = ('is_admin', 'is_user', 'is_active', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_admin', 'is_user', 'is_active', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2', 'is_admin', 'is_user'),
        }),
    )

# books/admin.py
from django.contrib import admin
from books.models import Book

@admin.register(Book)
class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'genre', 'added_by', 'is_available', 'date_added')
    list_filter = ('genre', 'is_available', 'date_added', 'added_by')
    search_fields = ('title', 'author', 'isbn', 'description')
    readonly_fields = ('date_added', 'date_modified')
    
    fieldsets = (
        ('Book Information', {
            'fields': ('title', 'author', 'isbn', 'genre', 'publication_date', 'page_count')
        }),
        ('Content', {
            'fields': ('description',)
        }),
        ('Management', {
            'fields': ('added_by', 'is_available')
        }),
        ('Metadata', {
            'fields': ('date_added', 'date_modified'),
            'classes': ('collapse',)
        }),
    )