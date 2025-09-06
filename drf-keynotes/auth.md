# Deep Dive: Django REST Framework Authentication & Authorization

## Table of Contents
1. [Core Concepts & Architecture](#core-concepts)
2. [Authentication Strategies](#authentication-strategies)
3. [Authorization & Permissions](#authorization-permissions)
4. [Implementation Patterns](#implementation-patterns)
5. [Security Best Practices](#security-best-practices)
6. [Real-World Examples](#real-world-examples)

---

## Core Concepts & Architecture {#core-concepts}

### Authentication vs Authorization: The Foundation

**Authentication** answers: "Who are you?"
**Authorization** answers: "What can you do?"

Think of it like entering a building:
- **Authentication**: Showing your ID at the front desk
- **Authorization**: Your ID badge determining which floors you can access

### DRF's Request Processing Pipeline

```python
# DRF processes requests in this order:
Request → Authentication → Permissions → Throttling → View
```

When a request hits your API:
1. **Authentication classes** identify the user
2. **Permission classes** determine if the action is allowed
3. **Throttling** controls rate limits
4. **View** processes the business logic

---

## Authentication Strategies {#authentication-strategies}

### 1. Session Authentication
**When to use**: Web applications with traditional login forms, same-domain requests

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ]
}

# views.py
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

class MyAPIView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
```

**Pros**: 
- Built-in CSRF protection
- Automatic session management
- Works seamlessly with Django's auth system

**Cons**:
- Stateful (sessions stored server-side)
- Not ideal for mobile apps or microservices
- CORS complexity for cross-domain requests

### 2. Token Authentication
**When to use**: Mobile apps, simple API access, single-server deployments

```python
# settings.py
INSTALLED_APPS = [
    'rest_framework.authtoken',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ]
}

# Create tokens for users
from rest_framework.authtoken.models import Token
token = Token.objects.create(user=user)

# Client usage
headers = {'Authorization': 'Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b'}
```

**Pros**:
- Simple implementation
- Stateless
- Good for testing and development

**Cons**:
- Tokens don't expire by default
- No built-in refresh mechanism
- Single token per user limitation

### 3. JWT Authentication
**When to use**: Microservices, mobile apps, distributed systems, when you need stateless auth with expiration

```python
# Installation: pip install djangorestframework-simplejwt

# settings.py
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ]
}

# urls.py
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view()),
    path('api/token/refresh/', TokenRefreshView.as_view()),
]
```

**Custom JWT Claims Example**:
```python
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['user_role'] = user.role
        token['department'] = user.department.name if user.department else None
        token['permissions'] = list(user.get_all_permissions())
        
        return token
```

**Pros**:
- Stateless and scalable
- Built-in expiration
- Can carry user information
- Industry standard

**Cons**:
- Slightly more complex setup
- Token size can grow with claims
- Revocation requires additional mechanisms

### 4. OAuth2 Authentication
**When to use**: Third-party integrations, enterprise SSO, when users have accounts elsewhere

```python
# Using django-oauth-toolkit
# settings.py
INSTALLED_APPS = [
    'oauth2_provider',
]

MIDDLEWARE = [
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
    ]
}

# Create OAuth2 application
from oauth2_provider.models import Application

Application.objects.create(
    name="My API",
    client_type=Application.CLIENT_CONFIDENTIAL,
    authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
)
```

### 5. Custom Authentication
**When to use**: Unique requirements, legacy systems integration, API keys with specific formats

```python
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model

User = get_user_model()

class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        
        if not api_key:
            return None
            
        try:
            # Look up user by API key
            user_profile = UserProfile.objects.get(api_key=api_key, is_active=True)
            return (user_profile.user, api_key)
        except UserProfile.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')
    
    def authenticate_header(self, request):
        return 'X-API-KEY'

# Usage
class MyAPIView(APIView):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
```

---

## Authorization & Permissions {#authorization-permissions}

### Built-in Permission Classes

#### 1. AllowAny
```python
from rest_framework.permissions import AllowAny

class PublicAPIView(APIView):
    permission_classes = [AllowAny]  # Anyone can access
```

#### 2. IsAuthenticated
```python
from rest_framework.permissions import IsAuthenticated

class PrivateAPIView(APIView):
    permission_classes = [IsAuthenticated]  # Must be logged in
```

#### 3. IsAdminUser
```python
from rest_framework.permissions import IsAdminUser

class AdminOnlyView(APIView):
    permission_classes = [IsAdminUser]  # Must be staff user
```

#### 4. IsAuthenticatedOrReadOnly
```python
from rest_framework.permissions import IsAuthenticatedOrReadOnly

class BlogPostViewSet(ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]
    # Anyone can read, only authenticated users can write
```

### Custom Permission Classes

#### Role-Based Permissions
```python
from rest_framework.permissions import BasePermission

class IsOwnerOrReadOnly(BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions for any request
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions only to the owner
        return obj.owner == request.user

class IsManagerOrReadOnly(BasePermission):
    """
    Allow managers to edit, others to read only
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return request.user.is_authenticated
        
        return request.user.is_authenticated and \
               hasattr(request.user, 'role') and \
               request.user.role == 'manager'

# Usage
class DocumentViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
```

#### Department-Based Permissions
```python
class IsSameDepartment(BasePermission):
    """
    Allow access only to users in the same department
    """
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
            
        user_dept = getattr(request.user, 'department', None)
        obj_dept = getattr(obj, 'department', None)
        
        return user_dept and obj_dept and user_dept == obj_dept

class EmployeeViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsSameDepartment]
```

#### Method-Based Permissions
```python
class CustomMethodPermission(BasePermission):
    """
    Different permissions for different HTTP methods
    """
    def has_permission(self, request, view):
        if request.method == 'GET':
            return request.user.has_perm('myapp.view_model')
        elif request.method == 'POST':
            return request.user.has_perm('myapp.add_model')
        elif request.method in ['PUT', 'PATCH']:
            return request.user.has_perm('myapp.change_model')
        elif request.method == 'DELETE':
            return request.user.has_perm('myapp.delete_model')
        
        return False
```

### Django's Built-in Permission System

#### Model-Level Permissions
```python
# models.py
class Document(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    
    class Meta:
        permissions = [
            ('can_publish', 'Can publish documents'),
            ('can_archive', 'Can archive documents'),
        ]

# Usage in views
from django.contrib.auth.decorators import permission_required

class DocumentView(APIView):
    def post(self, request):
        if not request.user.has_perm('myapp.can_publish'):
            return Response({'error': 'No publish permission'}, 
                          status=status.HTTP_403_FORBIDDEN)
```

#### Group-Based Permissions
```python
# Create groups and assign permissions
from django.contrib.auth.models import Group, Permission

# Create groups
editors_group = Group.objects.create(name='Editors')
viewers_group = Group.objects.create(name='Viewers')

# Assign permissions
view_perm = Permission.objects.get(codename='view_document')
change_perm = Permission.objects.get(codename='change_document')

viewers_group.permissions.add(view_perm)
editors_group.permissions.add(view_perm, change_perm)

# Assign users to groups
user.groups.add(editors_group)

# Check in views
class DocumentViewSet(ModelViewSet):
    def get_permissions(self):
        if self.action == 'list':
            permission_classes = [IsAuthenticated]
        elif self.action in ['create', 'update', 'partial_update']:
            permission_classes = [IsAuthenticated, IsInGroup('Editors')]
        else:
            permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
        
        return [permission() for permission in permission_classes]
```

---

## Implementation Patterns {#implementation-patterns}

### Multi-Tier Authentication Strategy

```python
# settings.py - Multi-tier authentication setup
from datetime import timedelta

# Multiple authentication methods
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'myapp.authentication.APIKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

# myapp/authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.utils import timezone
import hashlib
import secrets

User = get_user_model()

class APIKeyAuthentication(BaseAuthentication):
    """
    Custom API Key authentication for service-to-service communication
    """
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        
        if not api_key:
            return None
        
        try:
            # Hash the API key for comparison
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            api_key_obj = APIKey.objects.get(
                key_hash=key_hash, 
                is_active=True,
                expires_at__gt=timezone.now()
            )
            
            # Update last used
            api_key_obj.last_used = timezone.now()
            api_key_obj.save(update_fields=['last_used'])
            
            return (api_key_obj.user, api_key)
            
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid or expired API key')
    
    def authenticate_header(self, request):
        return 'X-API-KEY'

# myapp/models.py
class APIKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    key_hash = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'api_keys'
    
    @classmethod
    def create_key(cls, user, name, expires_days=365):
        """Generate a new API key"""
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        api_key = cls.objects.create(
            user=user,
            name=name,
            key_hash=key_hash,
            expires_at=timezone.now() + timedelta(days=expires_days)
        )
        
        # Return the raw key only once
        return api_key, raw_key

# myapp/permissions.py
from rest_framework.permissions import BasePermission
from django.contrib.auth.models import Group

class IsInGroup(BasePermission):
    """
    Custom permission to check if user belongs to a specific group
    """
    def __init__(self, group_name):
        self.group_name = group_name
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        return request.user.groups.filter(name=self.group_name).exists()

class HasModelPermission(BasePermission):
    """
    Check Django model permissions
    """
    def __init__(self, app_label, model_name, action='view'):
        self.permission = f"{app_label}.{action}_{model_name}"
    
    def has_permission(self, request, view):
        return request.user.has_perm(self.permission)

class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission to only allow owners or admins to edit
    """
    def has_object_permission(self, request, view, obj):
        # Admin users can access everything
        if request.user.is_staff:
            return True
        
        # Check if object has an owner field
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        
        return False

# myapp/views.py
class DocumentViewSet(ModelViewSet):
    """
    Example ViewSet with different permissions for different actions
    """
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions required for this view.
        """
        if self.action == 'list':
            permission_classes = [IsAuthenticated]
        elif self.action == 'create':
            permission_classes = [IsAuthenticated, IsInGroup('Authors')]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
        elif self.action == 'retrieve':
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated, IsAdminUser]
        
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        """
        Filter queryset based on user permissions
        """
        user = self.request.user
        
        if user.is_staff:
            return Document.objects.all()
        elif user.groups.filter(name='Managers').exists():
            # Managers see documents from their department
            return Document.objects.filter(
                department=user.profile.department
            )
        else:
            # Regular users see only their own documents
            return Document.objects.filter(owner=user)

# myapp/throttling.py
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

class LoginRateThrottle(UserRateThrottle):
    scope = 'login'

class APIKeyRateThrottle(UserRateThrottle):
    scope = 'apikey'
    
    def get_cache_key(self, request, view):
        if hasattr(request, 'auth') and isinstance(request.auth, str):
            # Use API key as identifier
            return self.cache_format % {
                'scope': self.scope,
                'ident': hashlib.md5(request.auth.encode()).hexdigest()
            }
        return super().get_cache_key(request, view)

# settings.py - Throttling configuration
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'login': '5/min',
        'apikey': '10000/hour'
    }
}
```

### Real-World Enterprise Example

```python
# Enterprise Role-Based Access Control (RBAC) Implementation

# models.py
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.core.exceptions import ValidationError

class CustomUser(AbstractUser):
    """Extended user model with enterprise fields"""
    employee_id = models.CharField(max_length=20, unique=True)
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True)
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    hire_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    def get_all_permissions(self, obj=None):
        """Get all permissions including role-based ones"""
        permissions = set(super().get_all_permissions(obj))
        
        # Add role-based permissions
        for role in self.roles.filter(is_active=True):
            permissions.update(role.permissions.values_list('codename', flat=True))
        
        return permissions
    
    def has_role(self, role_name):
        """Check if user has a specific role"""
        return self.roles.filter(name=role_name, is_active=True).exists()

class Department(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)
    manager = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
    
    def __str__(self):
        return self.name

class Role(models.Model):
    """Custom roles beyond Django's groups"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)
    users = models.ManyToManyField(CustomUser, through='UserRole', related_name='roles')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class UserRole(models.Model):
    """Through model for user-role relationship with additional fields"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='assigned_roles')
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ('user', 'role')

class Project(models.Model):
    """Example business model with complex permissions"""
    name = models.CharField(max_length=200)
    description = models.TextField()
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='owned_projects')
    members = models.ManyToManyField(CustomUser, through='ProjectMembership')
    status = models.CharField(max_length=20, choices=[
        ('planning', 'Planning'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ])
    confidentiality_level = models.CharField(max_length=20, choices=[
        ('public', 'Public'),
        ('internal', 'Internal'),
        ('confidential', 'Confidential'),
        ('restricted', 'Restricted'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

class ProjectMembership(models.Model):
    """Project membership with roles"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[
        ('member', 'Member'),
        ('lead', 'Lead'),
        ('reviewer', 'Reviewer'),
    ])
    joined_at = models.DateTimeField(auto_now_add=True)

# permissions.py
from rest_framework.permissions import BasePermission
from django.utils import timezone

class IsInRole(BasePermission):
    """Check if user has a specific role"""
    def __init__(self, role_name):
        self.role_name = role_name
    
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.has_role(self.role_name))

class DepartmentPermission(BasePermission):
    """Department-based access control"""
    
    def has_object_permission(self, request, view, obj):
        user = request.user
        
        # Admins can access everything
        if user.is_superuser:
            return True
        
        # Department managers can access their department's objects
        if hasattr(obj, 'department'):
            if user.department == obj.department and user == obj.department.manager:
                return True
        
        # Regular department members for read access
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return user.department == getattr(obj, 'department', None)
        
        return False

class ProjectPermission(BasePermission):
    """Complex project-based permissions"""
    
    def has_object_permission(self, request, view, obj):
        user = request.user
        
        if not user.is_authenticated:
            return False
        
        # Superusers and project owners have full access
        if user.is_superuser or obj.owner == user:
            return True
        
        # Check project membership
        try:
            membership = obj.projectmembership_set.get(user=user)
        except ProjectMembership.DoesNotExist:
            membership = None
        
        # Confidentiality level checks
        if obj.confidentiality_level == 'restricted':
            # Only owner and leads can access restricted projects
            return membership and membership.role == 'lead'
        elif obj.confidentiality_level == 'confidential':
            # Department members and project members
            return (user.department == obj.department or 
                   membership is not None)
        elif obj.confidentiality_level == 'internal':
            # Any authenticated user in the company
            return True
        else:  # public
            return True

class ConditionalPermission(BasePermission):
    """Permission that changes based on context"""
    
    def has_permission(self, request, view):
        user = request.user
        
        if not user.is_authenticated:
            return False
        
        # Time-based restrictions
        now = timezone.now()
        if now.hour < 6 or now.hour > 22:  # Outside business hours
            if not user.has_role('24x7_access'):
                return False
        
        # IP-based restrictions (example)
        client_ip = request.META.get('REMOTE_ADDR')
        if user.has_role('restricted_ip'):
            allowed_ips = ['192.168.1.0/24', '10.0.0.0/8']  # Example
            # IP validation logic here
            pass
        
        return True

# views.py
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class ProjectViewSet(ModelViewSet):
    """Complex ViewSet with multiple permission layers"""
    serializer_class = ProjectSerializer
    
    def get_permissions(self):
        """Dynamic permissions based on action"""
        if self.action == 'list':
            permission_classes = [IsAuthenticated]
        elif self.action == 'create':
            permission_classes = [IsAuthenticated, IsInRole('project_creator')]
        elif self.action in ['update', 'partial_update']:
            permission_classes = [IsAuthenticated, ProjectPermission]
        elif self.action == 'destroy':
            permission_classes = [IsAuthenticated, IsInRole('project_admin')]
        elif self.action == 'confidential_data':
            permission_classes = [IsAuthenticated, IsInRole('senior_manager')]
        else:
            permission_classes = [IsAuthenticated, ProjectPermission]
        
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        """Filter based on user permissions"""
        user = self.request.user
        
        if user.is_superuser:
            return Project.objects.all()
        
        # Build complex query based on user's roles and department
        queryset = Project.objects.none()
        
        # Own projects
        queryset |= Project.objects.filter(owner=user)
        
        # Projects user is a member of
        queryset |= Project.objects.filter(members=user)
        
        # Department projects (if appropriate confidentiality level)
        if user.department:
            queryset |= Project.objects.filter(
                department=user.department,
                confidentiality_level__in=['public', 'internal', 'confidential']
            )
        
        # Public projects
        queryset |= Project.objects.filter(confidentiality_level='public')
        
        return queryset.distinct()
    
    @action(detail=True, methods=['get'])
    def confidential_data(self, request, pk=None):
        """Action requiring special permissions"""
        project = self.get_object()
        
        # Additional business logic checks
        if project.confidentiality_level != 'restricted':
            return Response(
                {'error': 'This action is only available for restricted projects'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Return sensitive data
        return Response({
            'classified_info': 'Top secret project details...',
            'budget': project.budget,
            'sensitive_notes': project.internal_notes
        })

# middleware.py
import logging
from django.utils import timezone

logger = logging.getLogger('security')

class AuditMiddleware:
    """Log security-related events"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Before view
        start_time = timezone.now()
        
        response = self.get_response(request)
        
        # After view - log if it's an API request
        if request.path.startswith('/api/'):
            self.log_api_access(request, response, start_time)
        
        return response
    
    def log_api_access(self, request, response, start_time):
        """Log API access for audit trail"""
        duration = timezone.now() - start_time
        
        log_data = {
            'user': str(request.user) if request.user.is_authenticated else 'Anonymous',
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'duration_ms': duration.total_seconds() * 1000,
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'timestamp': start_time.isoformat()
        }
        
        # Log failed attempts as warnings
        if response.status_code >= 400:
            logger.warning('API_ACCESS_FAILED', extra=log_data)
        else:
            logger.info('API_ACCESS', extra=log_data)

# utils.py
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

User = get_user_model()

def check_user_permissions(user, action, resource_type, resource=None):
    """
    Centralized permission checking utility
    
    Args:
        user: User instance
        action: str - 'create', 'read', 'update', 'delete'
        resource_type: str - 'project', 'document', etc.
        resource: Model instance (for object-level permissions)
    
    Returns:
        bool: Whether user has permission
    """
    cache_key = f"perm_{user.id}_{action}_{resource_type}_{getattr(resource, 'id', 'none')}"
    cached_result = cache.get(cache_key)
    
    if cached_result is not None:
        return cached_result
    
    # Check basic authentication
    if not user.is_authenticated:
        result = False
    # Superuser bypass
    elif user.is_superuser:
        result = True
    # Resource-specific logic
    elif resource_type == 'project':
        result = _check_project_permission(user, action, resource)
    elif resource_type == 'document':
        result = _check_document_permission(user, action, resource)
    else:
        result = False
    
    # Cache for 5 minutes
    cache.set(cache_key, result, 300)
    return result

def _check_project_permission(user, action, project=None):
    """Project-specific permission logic"""
    if action == 'create':
        return user.has_role('project_creator') or user.has_role('manager')
    
    if project is None:
        return False
    
    # Owner has full access
    if project.owner == user:
        return True
    
    # Check membership
    membership = project.projectmembership_set.filter(user=user).first()
    
    if action == 'read':
        # Complex read permission logic based on confidentiality
        if project.confidentiality_level == 'public':
            return True
        elif project.confidentiality_level == 'internal':
            return True  # All authenticated users
        elif project.confidentiality_level == 'confidential':
            return membership is not None or user.department == project.department
        elif project.confidentiality_level == 'restricted':
            return membership and membership.role in ['lead', 'member']
    
    elif action in ['update', 'delete']:
        # Only leads and owners can modify
        return membership and membership.role == 'lead'
    
    return False

def _check_document_permission(user, action, document=None):
    """Document-specific permission logic"""
    # Implementation for document permissions
    if document is None:
        return user.has_perm(f'documents.{action}_document')
    
    # Owner check
    if hasattr(document, 'owner') and document.owner == user:
        return True
    
    # Department check for managers
    if (user.department == getattr(document, 'department', None) and 
        user == user.department.manager):
        return True
    
    return False

# decorators.py
from functools import wraps
from rest_framework.response import Response
from rest_framework import status

def require_role(role_name):
    """Decorator to require specific role"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {'error': 'Authentication required'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            if not request.user.has_role(role_name):
                return Response(
                    {'error': f'Role "{role_name}" required'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator

def audit_action(action_type):
    """Decorator to log important actions"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            # Log the action attempt
            logger.info(f'ACTION_ATTEMPT', extra={
                'user': str(request.user),
                'action': action_type,
                'path': request.path,
                'method': request.method,
                'timestamp': timezone.now().isoformat()
            })
            
            response = view_func(self, request, *args, **kwargs)
            
            # Log success/failure
            if response.status_code < 400:
                logger.info(f'ACTION_SUCCESS', extra={
                    'user': str(request.user),
                    'action': action_type,
                    'status_code': response.status_code
                })
            else:
                logger.warning(f'ACTION_FAILED', extra={
                    'user': str(request.user),
                    'action': action_type,
                    'status_code': response.status_code
                })
            
            return response
        return _wrapped_view
    return decorator

# management/commands/setup_roles.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from myapp.models import Role

class Command(BaseCommand):
    help = 'Set up initial roles and permissions'
    
    def handle(self, *args, **options):
        """Create standard enterprise roles"""
        
        roles_config = {
            'admin': {
                'description': 'System administrator',
                'permissions': ['*']  # All permissions
            },
            'manager': {
                'description': 'Department manager',
                'permissions': [
                    'add_project', 'change_project', 'view_project',
                    'add_document', 'change_document', 'view_document',
                    'view_user'
                ]
            },
            'project_creator': {
                'description': 'Can create new projects',
                'permissions': [
                    'add_project', 'view_project'
                ]
            },
            'senior_developer': {
                'description': 'Senior development role',
                'permissions': [
                    'view_project', 'change_project',
                    'add_document', 'change_document', 'view_document'
                ]
            },
            'developer': {
                'description': 'Regular developer',
                'permissions': [
                    'view_project', 'view_document', 'add_document'
                ]
            },
            '24x7_access': {
                'description': 'Can access system outside business hours',
                'permissions': []  # Special role for time-based access
            }
        }
        
        for role_name, config in roles_config.items():
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={'description': config['description']}
            )
            
            if created or self.options.get('update', False):
                self.stdout.write(f'Setting up role: {role_name}')
                
                # Clear existing permissions
                role.permissions.clear()
                
                if '*' in config['permissions']:
                    # Add all permissions
                    role.permissions.set(Permission.objects.all())
                else:
                    # Add specific permissions
                    for perm_codename in config['permissions']:
                        try:
                            permission = Permission.objects.get(codename=perm_codename)
                            role.permissions.add(permission)
                        except Permission.DoesNotExist:
                            self.stdout.write(
                                self.style.WARNING(f'Permission {perm_codename} not found')
                            )
                
                self.stdout.write(
                    self.style.SUCCESS(f'Role {role_name} configured successfully')
                )

# serializers.py
from rest_framework import serializers
from .models import Project, CustomUser, ProjectMembership

class ProjectSerializer(serializers.ModelSerializer):
    """Project serializer with permission-based field filtering"""
    
    # Sensitive fields that require special permissions
    budget = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    internal_notes = serializers.CharField(read_only=True)
    
    class Meta:
        model = Project
        fields = '__all__'
    
    def to_representation(self, instance):
        """Filter fields based on user permissions"""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            return data
        
        user = request.user
        
        # Remove sensitive fields based on confidentiality level
        if instance.confidentiality_level in ['confidential', 'restricted']:
            if not (user == instance.owner or 
                   user.has_role('senior_manager') or
                   user.is_superuser):
                data.pop('budget', None)
                data.pop('internal_notes', None)
        
        # Remove member information for non-members
        membership = instance.projectmembership_set.filter(user=user).first()
        if not membership and not user.is_superuser:
            data.pop('members', None)
        
        return data

class UserSerializer(serializers.ModelSerializer):
    """User serializer with privacy controls"""
    roles = serializers.StringRelatedField(many=True, read_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'department', 'roles', 'is_active']
    
    def to_representation(self, instance):
        """Filter user data based on viewer's permissions"""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            # Anonymous users get minimal info
            return {
                'id': data['id'],
                'first_name': data['first_name'],
                'last_name': data['last_name']
            }
        
        user = request.user
        
        # Users can see their own full info
        if user == instance:
            return data
        
        # Managers can see their department's users
        if (user.department == instance.department and 
            user == user.department.manager):
            return data
        
        # HR role can see all user info
        if user.has_role('hr'):
            return data
        
        # Others get limited info
        return {
            'id': data['id'],
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'department': data['department']
        }

# Exception handling
class InsufficientPermissionError(Exception):
    """Raised when user lacks required permissions"""
    pass

class SecurityViolationError(Exception):
    """Raised when a security policy is violated"""
    pass

# Context managers for permission checks
from contextlib import contextmanager

@contextmanager
def require_permission(user, permission_name):
    """Context manager to ensure permission before executing code block"""
    if not user.has_perm(permission_name):
        raise InsufficientPermissionError(f"Permission {permission_name} required")
    yield

# Usage example:
# with require_permission(request.user, 'myapp.delete_project'):
#     project.delete()
```

---

## Security Best Practices {#security-best-practices}

### 1. Token Security

**JWT Best Practices:**
```python
# Secure JWT configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),  # Short-lived
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,  # Generate new refresh token
    'BLACKLIST_AFTER_ROTATION': True,  # Invalidate old tokens
    'ALGORITHM': 'RS256',  # Use RSA instead of HMAC
    'SIGNING_KEY': private_key,  # Use RSA private key
    'VERIFYING_KEY': public_key,  # Use RSA public key
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}
```

**API Key Security:**
```python
import secrets
import hashlib
from django.utils.crypto import constant_time_compare

class SecureAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        
        if not api_key:
            return None
        
        # Rate limiting for failed attempts
        client_ip = request.META.get('REMOTE_ADDR')
        failed_attempts = cache.get(f'failed_auth_{client_ip}', 0)
        
        if failed_attempts >= 5:
            raise AuthenticationFailed('Too many failed attempts')
        
        # Constant-time comparison to prevent timing attacks
        try:
            stored_hash = get_api_key_hash(api_key)  # Your lookup logic
            if constant_time_compare(
                hashlib.sha256(api_key.encode()).hexdigest(), 
                stored_hash
            ):
                # Reset failed attempts on success
                cache.delete(f'failed_auth_{client_ip}')
                return (user, api_key)
        except:
            pass
        
        # Increment failed attempts
        cache.set(f'failed_auth_{client_ip}', failed_attempts + 1, 300)
        raise AuthenticationFailed('Invalid API key')
```

### 2. Input Validation and Sanitization

```python
from rest_framework import serializers
from django.core.validators import RegexValidator

class SecureProjectSerializer(serializers.ModelSerializer):
    # Validate input fields
    name = serializers.CharField(
        max_length=200,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\s\-_.]+$',
                message='Invalid characters in project name'
            )
        ]
    )
    
    def validate_description(self, value):
        """Custom validation for description field"""
        # Remove potentially dangerous content
        import bleach
        
        allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'li', 'ol']
        cleaned = bleach.clean(value, tags=allowed_tags, strip=True)
        
        return cleaned
    
    def validate(self, attrs):
        """Cross-field validation"""
        user = self.context['request'].user
        
        # Business rule: Users can't create projects with certain names
        forbidden_names = ['admin', 'test', 'system']
        if attrs['name'].lower() in forbidden_names:
            raise serializers.ValidationError(
                "Project name is reserved"
            )
        
        return attrs
```

### 3. Rate Limiting and Throttling

```python
from rest_framework.throttling import UserRateThrottle
from django.core.cache import cache

class CustomThrottle(UserRateThrottle):
    """Enhanced throttling with different rates for different actions"""
    
    def get_rate(self):
        """Dynamic rate based on user role and action"""
        user = self.get_ident()
        
        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            if self.request.user.has_role('premium'):
                return '10000/hour'
            elif self.request.user.has_role('basic'):
                return '1000/hour'
        
        return '100/hour'  # Anonymous users

class LoginThrottle(UserRateThrottle):
    """Strict throttling for login attempts"""
    scope = 'login'
    
    def get_cache_key(self, request, view):
        # Use IP address instead of user ID for login attempts
        ip = request.META.get('REMOTE_ADDR')
        return f'{self.scope}_{ip}'

# Progressive throttling
class ProgressiveThrottle(UserRateThrottle):
    """Throttle that gets stricter with repeated violations"""
    
    def allow_request(self, request, view):
        allowed = super().allow_request(request, view)
        
        if not allowed:
            # Increase throttling duration for repeated violations
            violations_key = f'throttle_violations_{self.get_ident()}'
            violations = cache.get(violations_key, 0)
            
            # Exponential backoff: 1min, 5min, 15min, 1hour
            backoff_duration = min(60 * (5 ** violations), 3600)
            cache.set(violations_key, violations + 1, backoff_duration)
        
        return allowed
```

### 4. Audit Logging and Monitoring

```python
import logging
import json
from django.utils import timezone

class SecurityLogger:
    """Centralized security event logging"""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_authentication_success(self, user, request, method='password'):
        """Log successful authentication"""
        self.logger.info('AUTH_SUCCESS', extra={
            'user_id': user.id,
            'username': user.username,
            'method': method,
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'timestamp': timezone.now().isoformat()
        })
    
    def log_authentication_failure(self, username, request, reason='invalid_credentials'):
        """Log failed authentication attempts"""
        self.logger.warning('AUTH_FAILURE', extra={
            'username': username,
            'reason': reason,
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'timestamp': timezone.now().isoformat()
        })
    
    def log_permission_denied(self, user, action, resource, request):
        """Log permission violations"""
        self.logger.warning('PERMISSION_DENIED', extra={
            'user_id': user.id if user.is_authenticated else None,
            'username': user.username if user.is_authenticated else 'anonymous',
            'action': action,
            'resource': str(resource),
            'path': request.path,
            'method': request.method,
            'ip_address': request.META.get('REMOTE_ADDR'),
            'timestamp': timezone.now().isoformat()
        })
    
    def log_security_event(self, event_type, user, details, request=None):
        """Generic security event logging"""
        log_data = {
            'event_type': event_type,
            'user_id': user.id if user and user.is_authenticated else None,
            'details': details,
            'timestamp': timezone.now().isoformat()
        }
        
        if request:
            log_data.update({
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'path': request.path
            })
        
        self.logger.info('SECURITY_EVENT', extra=log_data)

# Usage in views
security_logger = SecurityLogger()

class SecureLoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            
            if user:
                security_logger.log_authentication_success(
                    user, request, 'password'
                )
                # ... rest of login logic
            else:
                security_logger.log_authentication_failure(
                    serializer.validated_data['username'], 
                    request,
                    'invalid_credentials'
                )
                return Response(
                    {'error': 'Invalid credentials'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
```

---

## Real-World Implementation Strategies

### Microservices Authentication

When working with microservices, you often need to share authentication across services:

```python
# JWT Service Authentication
class JWTServiceAuthentication(BaseAuthentication):
    """Authentication for service-to-service communication"""
    
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header[7:]  # Remove 'Bearer '
        
        try:
            # Verify JWT with shared secret
            payload = jwt.decode(
                token, 
                settings.SERVICE_JWT_SECRET, 
                algorithms=['HS256']
            )
            
            # For service-to-service, create a special user
            service_user = User.objects.get_or_create(
                username=f"service_{payload['service_name']}",
                defaults={'is_active': True}
            )[0]
            
            return (service_user, token)
            
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid service token')
```

### Multi-Tenant Authentication

For SaaS applications with multiple tenants:

```python
class TenantAwarePermission(BasePermission):
    """Ensure users can only access their tenant's data"""
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Get tenant from various sources
        tenant_id = (
            request.headers.get('X-Tenant-ID') or
            request.GET.get('tenant_id') or
            getattr(request.user, 'tenant_id', None)
        )
        
        if not tenant_id:
            return False
        
        # Verify user belongs to this tenant
        return request.user.tenant_id == int(tenant_id)
    
    def has_object_permission(self, request, view, obj):
        # Ensure object belongs to user's tenant
        return getattr(obj, 'tenant_id', None) == request.user.tenant_id
```

### API Versioning with Different Auth Requirements

```python
class VersionedAuthenticationMixin:
    """Different auth requirements for different API versions"""
    
    def get_authenticators(self):
        # API v1: Token only
        if self.request.version == 'v1':
            return [TokenAuthentication()]
        
        # API v2: JWT preferred, token fallback  
        elif self.request.version == 'v2':
            return [JWTAuthentication(), TokenAuthentication()]
        
        # API v3: JWT only, stricter security
        elif self.request.version == 'v3':
            return [JWTAuthentication()]
        
        return super().get_authenticators()
    
    def get_permissions(self):
        # v3 requires stricter permissions
        if self.request.version == 'v3':
            return [IsAuthenticated(), IsInRole('verified_user')]
        
        return super().get_permissions()
```

---

## Key Takeaways

### Authentication Strategies Summary

1. **Session Auth**: Traditional web apps, same-domain
2. **Token Auth**: Simple APIs, mobile apps (with limitations)  
3. **JWT**: Modern, stateless, scalable - best for most APIs
4. **OAuth2**: Third-party integrations, enterprise SSO
5. **Custom**: Special requirements, legacy systems

### Permission Design Principles

1. **Principle of Least Privilege**: Users get minimum permissions needed
2. **Defense in Depth**: Multiple permission layers
3. **Fail Securely**: Default to deny, not allow
4. **Audit Everything**: Log all permission checks and violations
5. **Separation of Concerns**: Authentication ≠ Authorization

### Common Pitfalls to Avoid

1. **Don't hardcode permissions in views** - use reusable permission classes
2. **Don't trust client-side filtering** - always filter at the database level
3. **Don't expose sensitive data in serializers** - filter based on permissions
4. **Don't ignore object-level permissions** - model permissions aren't enough
5. **Don't skip rate limiting** - especially for authentication endpoints

### Testing Your Auth System

```python
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthenticationTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', 
            password='testpass123'
        )
        self.admin = User.objects.create_superuser(
            username='admin',
            password='adminpass123'
        )
    
    def test_unauthenticated_access(self):
        """Ensure protected endpoints require authentication"""
        response = self.client.get('/api/projects/')
        self.assertEqual(response.status_code, 401)
    
    def test_token_authentication(self):
        """Test token-based authentication works"""
        from rest_framework.authtoken.models import Token
        token = Token.objects.create(user=self.user)
        
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        response = self.client.get('/api/projects/')
        self.assertEqual(response.status_code, 200)
    
    def test_permission_enforcement(self):
        """Test that permissions are properly enforced"""
        self.client.force_authenticate(user=self.user)
        
        # Regular user shouldn't access admin endpoints
        response = self.client.get('/api/admin/users/')
        self.assertEqual(response.status_code, 403)
        
        # Admin should have access
        self.client.force_authenticate(user=self.admin)
        response = self.client.get('/api/admin/users/')
        self.assertEqual(response.status_code, 200)
```

The key to mastering DRF authentication and authorization is understanding that **security is layered**. Start simple with built-in classes, then customize as your requirements grow. Always think about the user's journey, the data they need access to, and the business rules that govern that access.

Remember: **Authentication gets you in the door, Authorization determines which rooms you can enter.**