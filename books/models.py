# books/models.py
from django.db import models
from django.conf import settings
from django.core.validators import MinLengthValidator

class Book(models.Model):
    """Book model for the book shelf application"""
    
    GENRE_CHOICES = [
        ('fiction', 'Fiction'),
        ('non_fiction', 'Non-Fiction'),
        ('mystery', 'Mystery'),
        ('romance', 'Romance'),
        ('sci_fi', 'Science Fiction'),
        ('fantasy', 'Fantasy'),
        ('biography', 'Biography'),
        ('history', 'History'),
        ('self_help', 'Self Help'),
        ('technical', 'Technical'),
        ('religious', 'Religious'),
    ]
    
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=100)
    # isbn = models.CharField(max_length=13, unique=True, blank=True, null=True)
    genre = models.CharField(max_length=20, choices=GENRE_CHOICES, default='fiction')
    publication_date = models.DateField(blank=True, null=True)
    description = models.TextField(blank=True)
    page_count = models.PositiveIntegerField(blank=True, null=True)
    isbn = models.CharField(
        max_length=13, 
        unique=True, 
        blank=True, 
        null=True,
        validators=[MinLengthValidator(10)],  # ISBN-10 or ISBN-13
        help_text="Enter ISBN-10 or ISBN-13 (optional)"
    )
    
    # User who added the book
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        related_name='books_added'
    )
    
    # Metadata
    date_added = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    is_available = models.BooleanField(default=True)

    class Meta:
        ordering = ['-date_added']
        verbose_name = 'Book'
        verbose_name_plural = 'Books'

    def __str__(self):
        return f"{self.title} by {self.author}"