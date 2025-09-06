# books/permissions.py
from rest_framework import permissions

class BookPermissions(permissions.BasePermission):
    """
    Custom permissions for book operations:
    - Unauthenticated: Read-only access (view books)
    - Users: Read and Create access
    - Admins: Full CRUD access
    """
    
    def has_permission(self, request, view):
        # Allow read access for unauthenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Require authentication for write operations
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Allow authenticated users to create books
        if request.method == 'POST':
            return request.user.is_user or request.user.is_admin
        
        return True
    
    def has_object_permission(self, request, view, obj):
        # Allow read access for everyone
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Admin users can modify any book
        if request.user.is_admin:
            return True
        
        # Regular users can only modify books they added
        if request.method in ['PUT', 'PATCH']:
            return obj.added_by == request.user
        
        # Only admins can delete books
        if request.method == 'DELETE':
            return request.user.is_admin
        
        return False