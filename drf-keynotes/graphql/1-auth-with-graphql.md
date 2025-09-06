Great question! GraphQL handles authentication differently from REST APIs since it uses a single endpoint. Instead of separate `/signin`, `/signup` endpoints, GraphQL uses **mutations** for authentication operations and **middleware/context** for handling authentication state. Let me show you how to implement this:

### Django GraphQL Authentication Setup
```py
# accounts/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return self.email

# ===================================
# accounts/schema.py
import graphene
from graphene_django import DjangoObjectType
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
import jwt
from django.conf import settings
from datetime import datetime, timedelta
from .models import User

class UserType(DjangoObjectType):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", 
                 "is_verified", "created_at", "updated_at")

class AuthPayload(graphene.ObjectType):
    """Response type for authentication mutations"""
    success = graphene.Boolean()
    message = graphene.String()
    token = graphene.String()
    user = graphene.Field(UserType)

# ===================================
# MUTATIONS
# ===================================

class SignUpMutation(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        username = graphene.String(required=True)
        password = graphene.String(required=True)
        first_name = graphene.String(required=True)
        last_name = graphene.String(required=True)

    Output = AuthPayload

    def mutate(self, info, email, username, password, first_name, last_name):
        try:
            # Validate password
            validate_password(password)
            
            # Check if user already exists
            if User.objects.filter(email=email).exists():
                return AuthPayload(
                    success=False,
                    message="User with this email already exists."
                )
            
            if User.objects.filter(username=username).exists():
                return AuthPayload(
                    success=False,
                    message="User with this username already exists."
                )

            # Create user
            user = User.objects.create_user(
                email=email,
                username=username,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            # Generate JWT token
            token = generate_jwt_token(user)

            return AuthPayload(
                success=True,
                message="User created successfully.",
                token=token,
                user=user
            )

        except ValidationError as e:
            return AuthPayload(
                success=False,
                message=f"Password validation error: {', '.join(e.messages)}"
            )
        except Exception as e:
            return AuthPayload(
                success=False,
                message=f"An error occurred: {str(e)}"
            )

class SignInMutation(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    Output = AuthPayload

    def mutate(self, info, email, password):
        try:
            # Authenticate user
            user = authenticate(username=email, password=password)
            
            if user is None:
                return AuthPayload(
                    success=False,
                    message="Invalid email or password."
                )

            if not user.is_active:
                return AuthPayload(
                    success=False,
                    message="User account is disabled."
                )

            # Log user in (for session-based auth)
            login(info.context, user)

            # Generate JWT token
            token = generate_jwt_token(user)

            return AuthPayload(
                success=True,
                message="User signed in successfully.",
                token=token,
                user=user
            )

        except Exception as e:
            return AuthPayload(
                success=False,
                message=f"An error occurred: {str(e)}"
            )

class SignOutMutation(graphene.Mutation):
    Output = AuthPayload

    def mutate(self, info):
        try:
            # Log user out (for session-based auth)
            logout(info.context)

            return AuthPayload(
                success=True,
                message="User signed out successfully."
            )

        except Exception as e:
            return AuthPayload(
                success=False,
                message=f"An error occurred: {str(e)}"
            )

class ChangePasswordMutation(graphene.Mutation):
    class Arguments:
        old_password = graphene.String(required=True)
        new_password = graphene.String(required=True)

    Output = AuthPayload

    def mutate(self, info, old_password, new_password):
        user = info.context.user
        
        if not user.is_authenticated:
            return AuthPayload(
                success=False,
                message="Authentication required."
            )

        try:
            # Validate old password
            if not user.check_password(old_password):
                return AuthPayload(
                    success=False,
                    message="Old password is incorrect."
                )

            # Validate new password
            validate_password(new_password, user)

            # Set new password
            user.set_password(new_password)
            user.save()

            return AuthPayload(
                success=True,
                message="Password changed successfully.",
                user=user
            )

        except ValidationError as e:
            return AuthPayload(
                success=False,
                message=f"Password validation error: {', '.join(e.messages)}"
            )

# ===================================
# QUERIES
# ===================================

class AuthQuery(graphene.ObjectType):
    me = graphene.Field(UserType)
    users = graphene.List(UserType)

    def resolve_me(self, info):
        user = info.context.user
        if user.is_authenticated:
            return user
        return None

    def resolve_users(self, info):
        user = info.context.user
        if user.is_authenticated and user.is_staff:
            return User.objects.all()
        return None

class AuthMutation(graphene.ObjectType):
    sign_up = SignUpMutation.Field()
    sign_in = SignInMutation.Field()
    sign_out = SignOutMutation.Field()
    change_password = ChangePasswordMutation.Field()

# ===================================
# HELPER FUNCTIONS
# ===================================

def generate_jwt_token(user):
    """Generate JWT token for user"""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),  # Token expires in 7 days
        'iat': datetime.utcnow(),
    }
    
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt_token(token):
    """Decode JWT token and return user"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.get(id=payload['user_id'])
        return user
    except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
        return None

# ===================================
# MIDDLEWARE FOR JWT AUTHENTICATION
# ===================================

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user = decode_jwt_token(token)
            
            if user:
                request.user = user

        return self.get_response(request)

# ===================================
# crm/schema.py (UPDATED)
import graphene
from graphene_django import DjangoObjectType
from .models import Customer
from accounts.schema import AuthQuery, AuthMutation

class CustomerType(DjangoObjectType):
    class Meta:
        model = Customer
        fields = "__all__"

class CRMQuery(graphene.ObjectType):
    # CRM queries
    all_customers = graphene.List(CustomerType)
    customer = graphene.Field(CustomerType, id=graphene.Int(required=True))

    def resolve_all_customers(self, info):
        # Only authenticated users can see customers
        if not info.context.user.is_authenticated:
            return []
        return Customer.objects.all()

    def resolve_customer(self, info, id):
        if not info.context.user.is_authenticated:
            return None
        try:
            return Customer.objects.get(pk=id)
        except Customer.DoesNotExist:
            return None

class CustomerMutation(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        email = graphene.String(required=True)
        phone = graphene.String()

    customer = graphene.Field(CustomerType)

    def mutate(self, info, name, email, phone=None):
        # Only authenticated users can create customers
        if not info.context.user.is_authenticated:
            raise Exception("Authentication required")
            
        customer = Customer(name=name, email=email, phone=phone)
        customer.save()
        return CustomerMutation(customer=customer)

class CRMMutation(graphene.ObjectType):
    create_customer = CustomerMutation.Field()

# Combine all queries and mutations
class Query(AuthQuery, CRMQuery, graphene.ObjectType):
    # Simple hello field
    hello = graphene.String(default_value="Hello World!")

class Mutation(AuthMutation, CRMMutation, graphene.ObjectType):
    pass

schema = graphene.Schema(query=Query, mutation=Mutation)

# ===================================
# settings.py (ADDITIONS)

# Add to INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'graphene_django',
    'accounts',  # ADD THIS
    'crm',
]

# Add to MIDDLEWARE
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'accounts.schema.JWTAuthenticationMiddleware',  # ADD THIS
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Specify custom user model
AUTH_USER_MODEL = 'accounts.User'

# JWT settings (optional)
JWT_SECRET_KEY = SECRET_KEY
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(days=7)
```

Now let me show you how to use these authentication mutations in your REST client:

### GraphQL Authentication Request Examples
```
### 1. SIGN UP (replaces POST /signup)
POST http://localhost:8000/graphql/
Content-Type: application/json

{
  "query": "mutation SignUp($email: String!, $username: String!, $password: String!, $firstName: String!, $lastName: String!) { signUp(email: $email, username: $username, password: $password, firstName: $firstName, lastName: $lastName) { success message token user { id email username firstName lastName } } }",
  "variables": {
    "email": "john@example.com",
    "username": "johndoe",
    "password": "securepassword123",
    "firstName": "John",
    "lastName": "Doe"
  }
}

###

### 2. SIGN IN (replaces POST /signin)
POST http://localhost:8000/graphql/
Content-Type: application/json

{
  "query": "mutation SignIn($email: String!, $password: String!) { signIn(email: $email, password: $password) { success message token user { id email username firstName lastName } } }",
  "variables": {
    "email": "john@example.com",
    "password": "securepassword123"
  }
}

###

### 3. GET CURRENT USER (replaces GET /me)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN_HERE

{
  "query": "{ me { id email username firstName lastName isVerified createdAt } }"
}

###

### 4. SIGN OUT (replaces POST /signout)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN_HERE

{
  "query": "mutation { signOut { success message } }"
}

###

### 5. CHANGE PASSWORD (replaces PUT /change-password)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN_HERE

{
  "query": "mutation ChangePassword($oldPassword: String!, $newPassword: String!) { changePassword(oldPassword: $oldPassword, newPassword: $newPassword) { success message } }",
  "variables": {
    "oldPassword": "securepassword123",
    "newPassword": "newsecurepassword456"
  }
}

###

### 6. ACCESS PROTECTED RESOURCE (authenticated customers)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN_HERE

{
  "query": "{ allCustomers { id name email phone createdAt } }"
}

###

### 7. CREATE CUSTOMER (requires authentication)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN_HERE

{
  "query": "mutation CreateCustomer($name: String!, $email: String!, $phone: String) { createCustomer(name: $name, email: $email, phone: $phone) { customer { id name email phone } } }",
  "variables": {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "phone": "555-1234"
  }
}

###

### 8. GET ALL USERS (admin only)
POST http://localhost:8000/graphql/
Content-Type: application/json
Authorization: Bearer YOUR_ADMIN_JWT_TOKEN_HERE

{
  "query": "{ users { id email username firstName lastName isVerified createdAt } }"
}
```

## Key Concepts for GraphQL Authentication:

### 1. **Mutations Replace REST Endpoints**
- `signUp` mutation → `POST /signup`
- `signIn` mutation → `POST /signin`
- `signOut` mutation → `POST /signout`
- `changePassword` mutation → `PUT /change-password`

### 2. **Authentication Methods**
The setup supports both:
- **Session-based auth** (traditional Django sessions)
- **JWT tokens** (for stateless authentication)

### 3. **Authorization in Resolvers**
Instead of middleware protecting specific endpoints, you check `info.context.user.is_authenticated` in your resolvers.

### 4. **JWT Token Usage**
- Client receives token from `signIn` or `signUp` mutation
- Client sends token in `Authorization: Bearer <token>` header
- Middleware automatically authenticates the user for subsequent requests

## Setup Steps:

1. **Install PyJWT**:
```bash
pip install PyJWT
```

2. **Create and run migrations**:
```bash
python manage.py makemigrations accounts
python manage.py makemigrations crm
python manage.py migrate
```

3. **Create a superuser**:
```bash
python manage.py createsuperuser
```

## Advantages of GraphQL Auth:

1. **Single Endpoint**: All auth operations through `/graphql/`
2. **Flexible Responses**: Get exactly the user data you need
3. **Type Safety**: Strong typing for all auth operations
4. **Consistent Error Handling**: Standardized error responses
5. **Introspection**: Auto-generated documentation

## Authentication Flow:

1. User signs up/signs in via GraphQL mutation
2. Server returns JWT token + user data
3. Client stores token and includes it in future requests
4. Server validates token and sets `request.user`
5. Resolvers check authentication status and return appropriate data

This approach gives you all the functionality of traditional REST auth endpoints while maintaining GraphQL's benefits!