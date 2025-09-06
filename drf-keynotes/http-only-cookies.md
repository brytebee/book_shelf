Yes, Django REST Framework can work with HTTP-only cookies, but it's not the default behavior. Here's how it works:

## Default DRF Behavior
By default, DRF doesn't use HTTP-only cookies for authentication. The standard authentication methods are:
- **Token Authentication**: Tokens sent in headers (`Authorization: Token <token>`)
- **Session Authentication**: Uses Django's session cookies (which can be HTTP-only)
- **JWT Authentication**: Tokens typically sent in headers

## HTTP-Only Cookies with DRF

### 1. Session Authentication (Built-in)
DRF's `SessionAuthentication` uses Django's session cookies, which can be configured as HTTP-only:

```python
# settings.py
SESSION_COOKIE_HTTPONLY = True  # Makes session cookies HTTP-only
SESSION_COOKIE_SECURE = True    # HTTPS only (for production)
SESSION_COOKIE_SAMESITE = 'Lax' # CSRF protection
```

### 2. Custom JWT with HTTP-Only Cookies
You can implement JWT authentication using HTTP-only cookies by creating custom authentication classes:

```python
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.conf import settings

class JWTCookieAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is not None:
            raw_token = self.get_raw_token(header)
        else:
            # Try to get token from HTTP-only cookie
            raw_token = request.COOKIES.get('access_token')
            
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token
```

### 3. Third-party Packages
There are packages that specifically handle HTTP-only cookies with JWT:
- `djangorestframework-jwt-cookies`
- `django-rest-auth` with cookie support

## Benefits of HTTP-only Cookies
- **XSS Protection**: JavaScript can't access HTTP-only cookies
- **Automatic inclusion**: Browsers automatically send cookies with requests
- **CSRF protection**: When combined with proper CSRF tokens

## Configuration Example
```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'your_app.authentication.JWTCookieAuthentication',
    ],
}

# Cookie settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # For HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'
```

Would you like me to show you how to implement JWT authentication with HTTP-only cookies for your book shelf application?