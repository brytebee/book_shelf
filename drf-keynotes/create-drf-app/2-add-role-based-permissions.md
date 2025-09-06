## Adding Role-Based Access Control

### 1. Update User Model
```python
# account/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('moderator', 'Moderator'),
        ('user', 'User'),
    ]
    
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def is_admin(self):
        return self.role == 'admin'
    
    def is_moderator(self):
        return self.role == 'moderator'
    
    def is_regular_user(self):
        return self.role == 'user'
    
    def has_admin_or_moderator_access(self):
        return self.role in ['admin', 'moderator']
```

### 2. Create Custom Permissions
```python
# account/permissions.py
from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin()

class IsModerator(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_moderator()

class IsAdminOrModerator(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.has_admin_or_moderator_access()

class IsOwnerOrAdminOrModerator(BasePermission):
    def has_object_permission(self, request, view, obj):
        # For user profile access
        if hasattr(obj, 'user'):
            return (request.user == obj.user or 
                   request.user.has_admin_or_moderator_access())
        return request.user == obj or request.user.has_admin_or_moderator_access()
```

### 3. Update Serializers
```python
# account/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'username', 'first_name', 'last_name', 'password', 'password_confirm')

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        user = authenticate(username=email, password=password)
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        
        attrs['user'] = user
        return attrs

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'role', 'date_joined')
        read_only_fields = ('id', 'date_joined')

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'role')
    
    def validate_role(self, value):
        # Only admins can change roles
        request = self.context.get('request')
        if request and not request.user.is_admin():
            if 'role' in self.initial_data:
                raise serializers.ValidationError("Only admins can change user roles")
        return value

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'role', 
                 'is_active', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login')
```

### 4. Update Views
```python
# account/views.py
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserSerializer,
    UserUpdateSerializer, AdminUserSerializer
)
from .permissions import IsAdmin, IsAdminOrModerator, IsOwnerOrAdminOrModerator

User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key,
            'message': 'Registration successful'
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key,
            'message': f'Welcome back, {user.first_name}!'
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        request.user.auth_token.delete()
        return Response({'message': 'Successfully logged out'})
    except:
        return Response({'error': 'Error logging out'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile(request):
    if request.method == 'GET':
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = UserUpdateSerializer(
            request.user, 
            data=request.data, 
            partial=True,
            context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(UserSerializer(request.user).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Admin-only endpoints
@api_view(['GET'])
@permission_classes([IsAdmin])
def list_users(request):
    users = User.objects.all()
    serializer = AdminUserSerializer(users, many=True)
    return Response(serializer.data)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAdmin])
def manage_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = AdminUserSerializer(user)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = AdminUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        if user == request.user:
            return Response({'error': 'Cannot delete your own account'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        user.delete()
        return Response({'message': 'User deleted successfully'})

# Moderator+ endpoints
@api_view(['GET'])
@permission_classes([IsAdminOrModerator])
def moderator_dashboard(request):
    user_count = User.objects.count()
    admin_count = User.objects.filter(role='admin').count()
    moderator_count = User.objects.filter(role='moderator').count()
    regular_user_count = User.objects.filter(role='user').count()
    
    return Response({
        'total_users': user_count,
        'admins': admin_count,
        'moderators': moderator_count,
        'regular_users': regular_user_count,
        'your_role': request.user.role
    })

@api_view(['PUT'])
@permission_classes([IsAdminOrModerator])
def toggle_user_status(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Prevent self-deactivation
    if user == request.user:
        return Response({'error': 'Cannot change your own status'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Moderators can't change admin status
    if not request.user.is_admin() and user.is_admin():
        return Response({'error': 'Insufficient permissions'}, 
                       status=status.HTTP_403_FORBIDDEN)
    
    user.is_active = not user.is_active
    user.save()
    
    return Response({
        'message': f'User {"activated" if user.is_active else "deactivated"} successfully',
        'user': AdminUserSerializer(user).data
    })
```

### 5. Update URLs
```python
# account/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    
    # Admin endpoints
    path('admin/users/', views.list_users, name='list_users'),
    path('admin/users/<int:user_id>/', views.manage_user, name='manage_user'),
    
    # Moderator+ endpoints
    path('dashboard/', views.moderator_dashboard, name='moderator_dashboard'),
    path('users/<int:user_id>/toggle-status/', views.toggle_user_status, name='toggle_user_status'),
]
```

### 6. Update Admin
```python
# account/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'username', 'first_name', 'last_name', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active', 'date_joined')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Role', {'fields': ('role',)}),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Role', {'fields': ('role',)}),
    )
```

### 7. Run Migration
```bash
python manage.py makemigrations
python manage.py migrate
```

### 8. Create Test Users
```python
# In Django shell: python manage.py shell
from account.models import User

# Create admin
admin = User.objects.create_user(
    email='admin@test.com',
    username='admin',
    first_name='Admin',
    last_name='User',
    password='admin123',
    role='admin'
)

# Create moderator
mod = User.objects.create_user(
    email='mod@test.com',
    username='moderator',
    first_name='Mod',
    last_name='User',
    password='mod123',
    role='moderator'
)
```

### 9. Test Role-Based Endpoints

**Admin Only:**
- `GET /api/auth/admin/users/` - List all users
- `GET/PUT/DELETE /api/auth/admin/users/<id>/` - Manage specific user

**Admin + Moderator:**
- `GET /api/auth/dashboard/` - Dashboard stats
- `PUT /api/auth/users/<id>/toggle-status/` - Activate/deactivate users

**All Authenticated:**
- `GET/PUT /api/auth/profile/` - View/update own profile

### 10. Usage Examples
```bash
# Login as admin
POST /api/auth/login/
{
    "email": "admin@test.com",
    "password": "admin123"
}

# View dashboard (admin/moderator only)
GET /api/auth/dashboard/
Headers: Authorization: Token <admin-token>

# List all users (admin only)
GET /api/auth/admin/users/
Headers: Authorization: Token <admin-token>

# Change user role (admin only)
PUT /api/auth/admin/users/2/
Headers: Authorization: Token <admin-token>
{
    "role": "moderator"
}
```

Now your authentication system supports role-based access control with proper permissions!