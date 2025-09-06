# accounts/permissions.py
from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users access.
    """
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.is_admin
        )

class IsRegularUser(permissions.BasePermission):
    """
    Custom permission to only allow regular users access.
    """
    def has_permission(self, request, view):
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.is_user
        )

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admins to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Admin users can access everything
        if request.user.is_admin:
            return True
        
        # Object owner can access their own objects
        return obj.added_by == request.user