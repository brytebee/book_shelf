# accounts/models.py
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email address is required')
        
        email = self.normalize_email(email)
        
        # Default role assignment
        if not extra_fields.get('is_admin'):
            extra_fields['is_user'] = True
            
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_user', False)

        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model for book_shelf application
    Supports Admin and User roles with specific permissions
    """
    
    # Basic Information
    email = models.EmailField(unique=True, verbose_name='Email Address')
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    
    # Role Management
    is_admin = models.BooleanField(
        default=False,
        help_text='Admin users can manage all books and users'
    )
    is_user = models.BooleanField(
        default=True,
        help_text='Regular users can view and add books'
    )
    
    # Status Fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    # Timestamps
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def clean(self):
        """Ensure proper role assignment"""
        if self.is_admin and self.is_user:
            raise ValidationError('User cannot have both Admin and User roles')
        if not self.is_admin and not self.is_user:
            raise ValidationError('User must have at least one role')

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    @property
    def role(self):
        """Return user's role as string"""
        return 'admin' if self.is_admin else 'user'

    @property
    def full_name(self):
        """Return user's full name"""
        return f"{self.first_name} {self.last_name}".strip()

    def __str__(self):
        return f"{self.email} ({self.role})"