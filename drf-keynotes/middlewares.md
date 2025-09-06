# Django Advanced Features: Complete Learning Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Django Middleware](#django-middleware)
3. [Django Signals](#django-signals)
4. [Advanced ORM Techniques](#advanced-orm-techniques)
5. [Caching Strategies](#caching-strategies)
6. [Practical Implementation](#practical-implementation)
7. [Best Practices](#best-practices)
8. [Common Pitfalls](#common-pitfalls)
9. [Assessment Questions](#assessment-questions)

---

## Introduction

This comprehensive lesson explores Django's advanced features that enable developers to build robust, scalable, and maintainable web applications. We'll dive deep into middleware architecture, event-driven programming with signals, advanced database interactions through ORM, and performance optimization techniques.

**Learning Objectives:**
- Master Django middleware for request/response processing
- Implement event-driven architecture using Django signals
- Execute complex database queries with advanced ORM techniques
- Apply caching strategies for performance optimization
- Follow best practices for scalable Django applications

---

## Django Middleware

### What is Middleware?

Middleware is Django's plugin system that processes requests and responses globally. It acts as a series of hooks that execute before and after view processing, allowing you to modify requests, responses, and handle exceptions at the application level.

### Middleware Lifecycle

```
Request → Middleware 1 → Middleware 2 → ... → View → ... → Middleware 2 → Middleware 1 → Response
```

### Types of Middleware Processing

1. **Request Processing**: Executed before the view
2. **Response Processing**: Executed after the view
3. **Exception Processing**: Handles exceptions during request processing
4. **View Processing**: Executed just before calling the view

### Creating Custom Middleware

#### Basic Middleware Structure

```python
class CustomMiddleware:
    def __init__(self, get_response):
        """
        Initialize the middleware.
        This is called once when Django starts.
        """
        self.get_response = get_response
        # One-time configuration and initialization

    def __call__(self, request):
        """
        Called for each request before the view is called.
        """
        # Code to be executed for each request before
        # the view (and later middleware) are called
        
        response = self.get_response(request)
        
        # Code to be executed for each request/response after
        # the view is called
        
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Called just before Django calls the view.
        Should return None or an HttpResponse object.
        """
        return None

    def process_exception(self, request, exception):
        """
        Called when a view raises an exception.
        Should return None or an HttpResponse object.
        """
        return None
```

### Practical Middleware Examples

#### 1. Request Logging Middleware

```python
import logging
import time
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Start timing
        start_time = time.time()
        
        # Log request details
        logger.info(f"Request: {request.method} {request.path}")
        logger.info(f"User: {request.user}")
        logger.info(f"IP: {self.get_client_ip(request)}")
        
        response = self.get_response(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Log response details
        logger.info(f"Response: {response.status_code}")
        logger.info(f"Processing time: {process_time:.3f}s")
        
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

#### 2. Authentication Middleware

```python
from django.http import JsonResponse
from django.contrib.auth.models import AnonymousUser

class CustomAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Paths that don't require authentication
        self.exempt_paths = ['/api/login/', '/api/register/', '/health/']

    def __call__(self, request):
        # Skip authentication for exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return self.get_response(request)
        
        # Check if user is authenticated
        if isinstance(request.user, AnonymousUser):
            return JsonResponse(
                {'error': 'Authentication required'}, 
                status=401
            )
        
        response = self.get_response(request)
        return response
```

#### 3. Rate Limiting Middleware

```python
import time
from django.core.cache import cache
from django.http import JsonResponse

class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit = 100  # requests per minute
        self.time_window = 60  # seconds

    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        cache_key = f"rate_limit:{client_ip}"
        
        # Get current request count
        current_requests = cache.get(cache_key, [])
        now = time.time()
        
        # Filter requests within time window
        current_requests = [
            req_time for req_time in current_requests 
            if now - req_time < self.time_window
        ]
        
        # Check rate limit
        if len(current_requests) >= self.rate_limit:
            return JsonResponse(
                {'error': 'Rate limit exceeded'}, 
                status=429
            )
        
        # Add current request
        current_requests.append(now)
        cache.set(cache_key, current_requests, self.time_window)
        
        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

### Middleware Configuration

Add middleware to `settings.py`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'apps.core.middleware.RequestLoggingMiddleware',
    'apps.core.middleware.RateLimitMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

---

## Django Signals

### Understanding Signals

Django signals implement the Observer pattern, allowing decoupled applications to get notified when certain actions occur. They enable event-driven architecture by allowing different parts of your application to communicate without tight coupling.

### Built-in Signals

#### Model Signals
- `pre_save` / `post_save`: Before/after model instance is saved
- `pre_delete` / `post_delete`: Before/after model instance is deleted
- `m2m_changed`: When ManyToManyField is changed

#### Request/Response Signals
- `request_started` / `request_finished`: Beginning/end of request processing
- `got_request_exception`: When Django encounters an exception while processing request

#### Database Signals
- `pre_migrate` / `post_migrate`: Before/after migration operations

### Creating Signal Receivers

#### Method 1: Using Decorators

```python
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, AuditLog

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create user profile when a new user is created."""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User, dispatch_uid="user_save_audit")
def audit_user_save(sender, instance, created, **kwargs):
    """Log user creation/update events."""
    action = "created" if created else "updated"
    AuditLog.objects.create(
        model_name="User",
        object_id=instance.pk,
        action=action,
        user=instance,
        details=f"User {instance.username} was {action}"
    )

@receiver(pre_delete, sender=User)
def audit_user_deletion(sender, instance, **kwargs):
    """Log user deletion events."""
    AuditLog.objects.create(
        model_name="User",
        object_id=instance.pk,
        action="deleted",
        details=f"User {instance.username} was deleted"
    )
```

#### Method 2: Manual Connection

```python
from django.db.models.signals import post_save
from django.contrib.auth.models import User

def user_notification_handler(sender, instance, created, **kwargs):
    if created:
        # Send welcome email
        send_welcome_email(instance.email)
        
        # Create notification
        create_notification(
            user=instance,
            message="Welcome to our platform!"
        )

# Connect the signal
post_save.connect(user_notification_handler, sender=User)
```

### Custom Signals

```python
from django.dispatch import Signal

# Define custom signals
payment_completed = Signal()
order_status_changed = Signal()

# In your business logic
class PaymentProcessor:
    def process_payment(self, payment):
        # Process payment logic
        result = self._charge_payment(payment)
        
        if result.success:
            # Send custom signal
            payment_completed.send(
                sender=self.__class__,
                payment=payment,
                amount=payment.amount,
                timestamp=timezone.now()
            )

# Signal receivers
@receiver(payment_completed)
def handle_payment_completion(sender, payment, amount, timestamp, **kwargs):
    # Update order status
    payment.order.status = 'paid'
    payment.order.save()
    
    # Send confirmation email
    send_payment_confirmation_email(payment.order.user.email, amount)
    
    # Update inventory
    update_inventory_for_order(payment.order)
```

### Advanced Signal Patterns

#### Conditional Signal Processing

```python
@receiver(post_save, sender=Order)
def process_order_update(sender, instance, created, **kwargs):
    """Process order updates with conditional logic."""
    
    if created:
        # New order created
        send_order_confirmation_email(instance)
        update_inventory(instance)
        
    else:
        # Existing order updated
        if instance.status == 'shipped':
            send_shipping_notification(instance)
        elif instance.status == 'cancelled':
            restore_inventory(instance)
            process_refund(instance)
```

#### Signal-based Cache Invalidation

```python
from django.core.cache import cache

@receiver(post_save, sender=Product)
@receiver(post_delete, sender=Product)
def invalidate_product_cache(sender, instance, **kwargs):
    """Invalidate cached product data when product changes."""
    cache_keys = [
        f'product:{instance.pk}',
        f'category:{instance.category.pk}:products',
        'featured_products',
        'all_products_count'
    ]
    
    cache.delete_many(cache_keys)
```

---

## Advanced ORM Techniques

### Complex Queries and Annotations

#### Aggregations and Annotations

```python
from django.db.models import Count, Sum, Avg, F, Case, When, DecimalField
from django.db.models.functions import Coalesce

# Basic aggregations
from myapp.models import Order, OrderItem, Product

# Count orders per user
user_order_counts = User.objects.annotate(
    order_count=Count('orders')
).filter(order_count__gt=5)

# Calculate total sales per product
product_sales = Product.objects.annotate(
    total_sales=Sum('orderitem__quantity'),
    total_revenue=Sum(
        F('orderitem__quantity') * F('orderitem__price'),
        output_field=DecimalField(max_digits=10, decimal_places=2)
    )
).order_by('-total_revenue')

# Complex conditional aggregations
order_stats = Order.objects.aggregate(
    total_orders=Count('id'),
    completed_orders=Count(
        Case(When(status='completed', then=1))
    ),
    average_value=Avg('total_amount'),
    total_revenue=Sum(
        Case(
            When(status='completed', then='total_amount'),
            default=0,
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )
    )
)
```

#### Subqueries and Exists

```python
from django.db.models import OuterRef, Subquery, Exists

# Find users with their latest order
latest_orders = Order.objects.filter(
    user=OuterRef('pk')
).order_by('-created_at')

users_with_latest_order = User.objects.annotate(
    latest_order_date=Subquery(
        latest_orders.values('created_at')[:1]
    ),
    latest_order_total=Subquery(
        latest_orders.values('total_amount')[:1]
    )
).filter(latest_order_date__isnull=False)

# Find products that have never been ordered
never_ordered_products = Product.objects.filter(
    ~Exists(OrderItem.objects.filter(product=OuterRef('pk')))
)

# Find users who have placed orders in the last 30 days
recent_customers = User.objects.filter(
    Exists(
        Order.objects.filter(
            user=OuterRef('pk'),
            created_at__gte=timezone.now() - timedelta(days=30)
        )
    )
)
```

#### Window Functions

```python
from django.db.models import F, Window
from django.db.models.functions import Rank, RowNumber, Lag

# Rank products by sales within each category
ranked_products = Product.objects.annotate(
    sales_rank=Window(
        expression=Rank(),
        partition_by=[F('category')],
        order_by=F('total_sales').desc()
    )
).order_by('category', 'sales_rank')

# Calculate running totals
orders_with_running_total = Order.objects.annotate(
    running_total=Window(
        expression=Sum('total_amount'),
        order_by=F('created_at').asc()
    )
).order_by('created_at')
```

### Database Functions and Expressions

```python
from django.db.models.functions import (
    Upper, Lower, Concat, Length, Substring,
    Extract, TruncDate, TruncMonth, Coalesce
)

# String functions
formatted_users = User.objects.annotate(
    full_name=Concat('first_name', Value(' '), 'last_name'),
    username_upper=Upper('username'),
    email_length=Length('email')
)

# Date functions
monthly_sales = Order.objects.annotate(
    order_month=TruncMonth('created_at')
).values('order_month').annotate(
    total_sales=Sum('total_amount'),
    order_count=Count('id')
).order_by('order_month')

# Extract date parts
orders_by_weekday = Order.objects.annotate(
    weekday=Extract('created_at', 'week_day')
).values('weekday').annotate(
    count=Count('id')
)
```

### Custom Managers and QuerySets

```python
class ActiveProductQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)
    
    def in_stock(self):
        return self.filter(stock_quantity__gt=0)
    
    def by_category(self, category):
        return self.filter(category=category)
    
    def featured(self):
        return self.filter(is_featured=True)
    
    def with_sales_data(self):
        return self.annotate(
            total_sold=Coalesce(Sum('orderitem__quantity'), 0),
            revenue=Coalesce(
                Sum(F('orderitem__quantity') * F('orderitem__price')), 
                0
            )
        )

class ProductManager(models.Manager):
    def get_queryset(self):
        return ActiveProductQuerySet(self.model, using=self._db)
    
    def active(self):
        return self.get_queryset().active()
    
    def in_stock(self):
        return self.get_queryset().in_stock()
    
    def bestsellers(self):
        return self.get_queryset().with_sales_data().order_by('-total_sold')

class Product(models.Model):
    name = models.CharField(max_length=200)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    stock_quantity = models.IntegerField(default=0)
    is_featured = models.BooleanField(default=False)
    
    objects = ProductManager()
    
    def __str__(self):
        return self.name
```

### Raw SQL When Needed

```python
from django.db import connection

def get_sales_report(start_date, end_date):
    """Complex sales report using raw SQL."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                p.name as product_name,
                c.name as category_name,
                SUM(oi.quantity) as total_sold,
                SUM(oi.quantity * oi.price) as total_revenue,
                AVG(oi.price) as average_price
            FROM myapp_product p
            JOIN myapp_category c ON p.category_id = c.id
            JOIN myapp_orderitem oi ON p.id = oi.product_id
            JOIN myapp_order o ON oi.order_id = o.id
            WHERE o.created_at BETWEEN %s AND %s
            GROUP BY p.id, p.name, c.name
            ORDER BY total_revenue DESC
        """, [start_date, end_date])
        
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

# Using raw SQL with model instances
def get_top_customers(limit=10):
    """Get top customers using raw SQL."""
    return User.objects.raw("""
        SELECT u.*, 
               COUNT(o.id) as order_count,
               SUM(o.total_amount) as total_spent
        FROM auth_user u
        LEFT JOIN myapp_order o ON u.id = o.user_id
        GROUP BY u.id
        ORDER BY total_spent DESC
        LIMIT %s
    """, [limit])
```

---

## Caching Strategies

### Cache Configuration

```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Cache timeouts
CACHE_TTL = 60 * 15  # 15 minutes
```

### Caching Patterns

#### 1. Low-level Cache API

```python
from django.core.cache import cache
from django.conf import settings

class ProductService:
    @staticmethod
    def get_product(product_id):
        cache_key = f'product:{product_id}'
        product = cache.get(cache_key)
        
        if product is None:
            try:
                product = Product.objects.select_related('category').get(pk=product_id)
                cache.set(cache_key, product, settings.CACHE_TTL)
            except Product.DoesNotExist:
                cache.set(cache_key, 'NOT_FOUND', 60)  # Cache misses
                return None
        
        return product if product != 'NOT_FOUND' else None

    @staticmethod
    def get_featured_products():
        cache_key = 'featured_products'
        products = cache.get(cache_key)
        
        if products is None:
            products = list(
                Product.objects.filter(is_featured=True)
                .select_related('category')
                .order_by('-created_at')[:10]
            )
            cache.set(cache_key, products, settings.CACHE_TTL)
        
        return products
```

#### 2. Cache Decorators

```python
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator

# Function-based view caching
@cache_page(60 * 15)  # Cache for 15 minutes
def product_list(request):
    products = Product.objects.active().with_sales_data()
    return render(request, 'products/list.html', {'products': products})

# Method-based view caching
@method_decorator(cache_page(60 * 15), name='get')
class ProductListView(ListView):
    model = Product
    template_name = 'products/list.html'
    
    def get_queryset(self):
        return Product.objects.active().with_sales_data()
```

#### 3. Template Fragment Caching

```html
<!-- In templates -->
{% load cache %}

{% cache 900 product_grid category.id %}
    <div class="product-grid">
        {% for product in products %}
            <div class="product-card">
                <h3>{{ product.name }}</h3>
                <p>${{ product.price }}</p>
            </div>
        {% endfor %}
    </div>
{% endcache %}

<!-- Conditional caching -->
{% cache 900 user_dashboard user.id user.last_login %}
    <div class="dashboard">
        <!-- User-specific content -->
    </div>
{% endcache %}
```

#### 4. Advanced Caching Utilities

```python
import hashlib
from django.core.cache import cache
from functools import wraps

def cache_result(timeout=300, key_prefix=''):
    """Decorator for caching function results."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            key_data = f"{key_prefix}:{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            result = cache.get(cache_key)
            if result is None:
                result = func(*args, **kwargs)
                cache.set(cache_key, result, timeout)
            
            return result
        return wrapper
    return decorator

# Usage
@cache_result(timeout=600, key_prefix='analytics')
def get_sales_analytics(start_date, end_date, category_id=None):
    # Expensive analytics calculation
    pass

class CacheManager:
    """Centralized cache management."""
    
    @staticmethod
    def invalidate_pattern(pattern):
        """Invalidate cache keys matching a pattern."""
        from django_redis import get_redis_connection
        
        redis_conn = get_redis_connection("default")
        keys = redis_conn.keys(pattern)
        if keys:
            redis_conn.delete(*keys)
    
    @staticmethod
    def warm_cache():
        """Pre-populate important cache entries."""
        # Warm up featured products
        ProductService.get_featured_products()
        
        # Warm up popular categories
        categories = Category.objects.filter(is_popular=True)
        for category in categories:
            ProductService.get_products_by_category(category.id)
```

---

## Practical Implementation

### Project Structure

```
project-root/
├── apps/
│   ├── core/
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── logging.py
│   │   │   ├── auth.py
│   │   │   └── rate_limiting.py
│   │   ├── signals/
│   │   │   ├── __init__.py
│   │   │   ├── handlers.py
│   │   │   └── custom_signals.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── cache.py
│   │       └── database.py
│   ├── products/
│   │   ├── models.py
│   │   ├── managers.py
│   │   ├── services.py
│   │   └── views.py
│   └── users/
│       ├── models.py
│       ├── signals.py
│       └── views.py
├── config/
│   ├── settings/
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   └── urls.py
└── manage.py
```

### Integration Example

```python
# apps/products/services.py
from django.core.cache import cache
from django.db.models import F, Sum, Count
from .models import Product

class ProductService:
    @staticmethod
    @cache_result(timeout=600)
    def get_trending_products(limit=10):
        """Get trending products with caching."""
        return Product.objects.annotate(
            trend_score=F('view_count') + F('purchase_count') * 2
        ).order_by('-trend_score')[:limit]
    
    @staticmethod
    def update_product_views(product_id):
        """Update product view count and invalidate cache."""
        Product.objects.filter(pk=product_id).update(
            view_count=F('view_count') + 1
        )
        
        # Invalidate related caches
        cache_keys = [
            f'product:{product_id}',
            'trending_products',
            f'product_category:{Product.objects.get(pk=product_id).category_id}'
        ]
        cache.delete_many(cache_keys)

# apps/products/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Product
from .services import ProductService

@receiver(post_save, sender=Product)
def product_saved_handler(sender, instance, created, **kwargs):
    """Handle product save events."""
    if created:
        # New product notification
        send_new_product_notification.delay(instance.id)
    
    # Invalidate caches
    ProductService.invalidate_product_caches(instance.id)

@receiver(post_delete, sender=Product)
def product_deleted_handler(sender, instance, **kwargs):
    """Handle product deletion."""
    ProductService.invalidate_product_caches(instance.id)
```

---

## Best Practices

### Middleware Best Practices

1. **Keep middleware lightweight**: Avoid heavy database queries or external API calls
2. **Order matters**: Place middleware in the correct order in `MIDDLEWARE` setting
3. **Use `dispatch_uid`**: Prevent duplicate signal connections
4. **Handle exceptions**: Always handle potential exceptions gracefully
5. **Document behavior**: Clearly document what each middleware does

### Signal Best Practices

1. **Use `dispatch_uid`**: Prevent duplicate receiver registration
2. **Keep receivers fast**: Use background tasks for heavy operations
3. **Be careful with database operations**: Avoid infinite loops
4. **Test thoroughly**: Signal behavior can be complex to debug
5. **Consider alternatives**: Sometimes decorators or managers are better

### ORM Best Practices

1. **Use `select_related()` and `prefetch_related()`**: Minimize database queries
2. **Leverage database functions**: Push computation to the database when possible
3. **Use `only()` and `defer()`**: Select only needed fields
4. **Index properly**: Ensure your queries are properly indexed
5. **Monitor query performance**: Use Django Debug Toolbar in development

### Caching Best Practices

1. **Cache at the right level**: Choose between view-level, template-fragment, or low-level caching
2. **Use appropriate timeouts**: Balance freshness with performance
3. **Implement cache invalidation**: Ensure data consistency
4. **Consider cache warming**: Pre-populate important data
5. **Monitor cache hit rates**: Ensure your caching strategy is effective

---

## Common Pitfalls

### Middleware Pitfalls

- **Incorrect ordering**: Middleware order affects functionality
- **Performance issues**: Heavy operations in middleware affect all requests
- **Exception handling**: Unhandled exceptions can break the request cycle
- **State management**: Middleware instances are shared across requests

### Signal Pitfalls

- **Infinite loops**: Signals triggering more signals
- **Performance**: Heavy operations in signal handlers
- **Testing complexity**: Signals can make testing more complex
- **Duplicate registration**: Same receiver registered multiple times

### ORM Pitfalls

- **N+1 queries**: Not using `select_related()` or `prefetch_related()`
- **Loading unused data**: Not using `only()` or `defer()`
- **Complex queries in Python**: Not leveraging database capabilities
- **Memory issues**: Loading too much data at once

### Caching Pitfalls

- **Cache invalidation**: Forgetting to invalidate stale data
- **Over-caching**: Caching data that changes frequently
- **Under-caching**: Missing opportunities for performance gains
- **Cache stampede**: Multiple processes regenerating same cache

---

## Assessment Questions

### Question 1: Middleware Order
**What happens if a middleware's `__init__()` method raises `MiddlewareNotUsed`?**

A) The middleware will be called again with different arguments  
B) The middleware will be removed from the middleware chain  
C) Django will raise an error  
D) Django will restart the server

**Answer: B** - The middleware will be removed from the middleware chain

### Question 2: Signal Benefits
**What is the main advantage of using Django signals?**

A) To increase the speed of request processing  
B) To decouple applications that need to be notified of events  
C) To execute code asynchronously  
D) To manage database transactions

**Answer: B** - To decouple applications that need to be notified of events

### Question 3: ORM Methods
**Which Django ORM method is used to retrieve a single object from the database that matches a query?**

A) `all()`  
B) `get()`  
C) `filter()`  
D) `exclude()`

**Answer: B** - `get()`

### Question 4: Signal Registration
**Which of the following methods connects a receiver function to a signal?**

A) `Signal.notify`  
B) `Signal.connect`  
C) `Signal.emit`  
D) `Signal.link`

**Answer: B** - `Signal.connect`

### Question 5: Middleware Responsibility
**Which method in middleware is responsible for processing each request and returning a response?**

A) `__call__`  
B) `get_response`  
C) `__init__`  
D) `process_view`

**Answer: A** - `__call__`

### Practical Exercise

Create a complete Django application that implements:

1. **Custom Middleware**: Create a logging middleware that tracks API usage
2. **Signal Handlers**: Implement automatic profile creation and audit logging
3. **Advanced ORM**: Build complex analytics queries
4. **Caching Strategy**: Implement multi-level caching

#### Exercise Requirements

```python
# Step 1: Create the models
# apps/ecommerce/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Product(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock_quantity = models.IntegerField(default=0)
    is_featured = models.BooleanField(default=False)
    view_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2)

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('created', 'Created'),
        ('updated', 'Updated'),
        ('deleted', 'Deleted'),
    ]
    
    model_name = models.CharField(max_length=50)
    object_id = models.IntegerField()
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

# Step 2: Create middleware
# apps/core/middleware/api_tracking.py

import time
import json
from django.core.cache import cache
from django.utils import timezone

class APITrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        
        # Track API endpoint usage
        if request.path.startswith('/api/'):
            self._track_api_usage(request)
        
        response = self.get_response(request)
        
        # Log response time for API calls
        if request.path.startswith('/api/'):
            process_time = time.time() - start_time
            self._log_api_response(request, response, process_time)
        
        return response
    
    def _track_api_usage(self, request):
        endpoint = request.path
        method = request.method
        user_id = request.user.id if request.user.is_authenticated else None
        
        # Daily usage tracking
        today = timezone.now().date()
        cache_key = f"api_usage:{today}:{endpoint}:{method}"
        
        current_count = cache.get(cache_key, 0)
        cache.set(cache_key, current_count + 1, timeout=86400)  # 24 hours
        
        # User-specific tracking
        if user_id:
            user_cache_key = f"user_api_usage:{today}:{user_id}"
            user_count = cache.get(user_cache_key, 0)
            cache.set(user_cache_key, user_count + 1, timeout=86400)
    
    def _log_api_response(self, request, response, process_time):
        # Log slow API calls
        if process_time > 1.0:  # Log calls taking more than 1 second
            import logging
            logger = logging.getLogger('slow_api')
            logger.warning(
                f"Slow API call: {request.method} {request.path} "
                f"took {process_time:.3f}s - Status: {response.status_code}"
            )

# Step 3: Create signal handlers
# apps/ecommerce/signals.py

from django.db.models.signals import post_save, pre_delete, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, Product, Order, AuditLog

@receiver(post_save, sender=User, dispatch_uid="create_user_profile")
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when User is created."""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User, dispatch_uid="audit_user_save")
def audit_user_save(sender, instance, created, **kwargs):
    """Log user creation/update events."""
    action = "created" if created else "updated"
    AuditLog.objects.create(
        model_name="User",
        object_id=instance.pk,
        action=action,
        user=instance,
        details=f"User {instance.username} was {action}"
    )

@receiver(post_save, sender=Product, dispatch_uid="audit_product_save")
def audit_product_save(sender, instance, created, **kwargs):
    """Log product creation/update events."""
    from django.core.cache import cache
    
    action = "created" if created else "updated"
    AuditLog.objects.create(
        model_name="Product",
        object_id=instance.pk,
        action=action,
        details=f"Product {instance.name} was {action}"
    )
    
    # Invalidate product-related caches
    cache_keys = [
        f'product:{instance.pk}',
        'featured_products',
        f'category:{instance.category_id}:products',
    ]
    cache.delete_many(cache_keys)

@receiver(post_save, sender=Order, dispatch_uid="process_order_status_change")
def process_order_status_change(sender, instance, created, **kwargs):
    """Process order status changes."""
    if not created:
        # Check if status changed to 'paid'
        if instance.status == 'paid':
            # Update product stock
            for item in instance.items.all():
                Product.objects.filter(pk=item.product.pk).update(
                    stock_quantity=models.F('stock_quantity') - item.quantity
                )

@receiver(pre_delete, sender=Product, dispatch_uid="audit_product_delete")
def audit_product_delete(sender, instance, **kwargs):
    """Log product deletion events."""
    AuditLog.objects.create(
        model_name="Product",
        object_id=instance.pk,
        action="deleted",
        details=f"Product {instance.name} was deleted"
    )

# Step 4: Advanced ORM queries and services
# apps/ecommerce/services.py

from django.db.models import (
    Count, Sum, Avg, F, Q, Case, When, 
    DecimalField, IntegerField
)
from django.db.models.functions import TruncMonth, Coalesce
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from .models import Product, Order, User, Category

class AnalyticsService:
    @staticmethod
    def get_product_performance_report():
        """Generate comprehensive product performance report."""
        cache_key = 'product_performance_report'
        report = cache.get(cache_key)
        
        if report is None:
            report = Product.objects.select_related('category').annotate(
                total_sold=Coalesce(
                    Sum('orderitem__quantity'), 0, 
                    output_field=IntegerField()
                ),
                total_revenue=Coalesce(
                    Sum(F('orderitem__quantity') * F('orderitem__price')), 
                    0, 
                    output_field=DecimalField(max_digits=10, decimal_places=2)
                ),
                order_count=Count('orderitem__order', distinct=True),
                avg_order_quantity=Coalesce(
                    Avg('orderitem__quantity'), 0,
                    output_field=DecimalField(max_digits=5, decimal_places=2)
                )
            ).values(
                'id', 'name', 'category__name', 'price', 'stock_quantity',
                'total_sold', 'total_revenue', 'order_count', 'avg_order_quantity'
            ).order_by('-total_revenue')
            
            cache.set(cache_key, list(report), timeout=3600)  # Cache for 1 hour
        
        return report
    
    @staticmethod
    def get_customer_segmentation():
        """Segment customers based on purchase behavior."""
        cache_key = 'customer_segmentation'
        segmentation = cache.get(cache_key)
        
        if segmentation is None:
            thirty_days_ago = timezone.now() - timedelta(days=30)
            ninety_days_ago = timezone.now() - timedelta(days=90)
            
            segmentation = User.objects.annotate(
                total_orders=Count('orders'),
                total_spent=Coalesce(Sum('orders__total_amount'), 0),
                avg_order_value=Coalesce(Avg('orders__total_amount'), 0),
                recent_orders=Count(
                    'orders',
                    filter=Q(orders__created_at__gte=thirty_days_ago)
                ),
                segment=Case(
                    When(
                        total_spent__gte=1000,
                        recent_orders__gte=1,
                        then=Value('VIP')
                    ),
                    When(
                        total_spent__gte=500,
                        total_orders__gte=3,
                        then=Value('Loyal')
                    ),
                    When(
                        recent_orders__gte=1,
                        then=Value('Active')
                    ),
                    When(
                        total_orders__gte=1,
                        then=Value('Inactive')
                    ),
                    default=Value('New'),
                    output_field=CharField(max_length=20)
                )
            ).values(
                'id', 'username', 'email', 'total_orders', 
                'total_spent', 'avg_order_value', 'segment'
            ).order_by('-total_spent')
            
            cache.set(cache_key, list(segmentation), timeout=3600)
        
        return segmentation
    
    @staticmethod
    def get_monthly_sales_trend(months=12):
        """Get monthly sales trend for the last N months."""
        cache_key = f'monthly_sales_trend_{months}'
        trend = cache.get(cache_key)
        
        if trend is None:
            start_date = timezone.now() - timedelta(days=months * 30)
            
            trend = Order.objects.filter(
                created_at__gte=start_date,
                status__in=['paid', 'shipped', 'delivered']
            ).annotate(
                month=TruncMonth('created_at')
            ).values('month').annotate(
                total_sales=Sum('total_amount'),
                order_count=Count('id'),
                avg_order_value=Avg('total_amount')
            ).order_by('month')
            
            cache.set(cache_key, list(trend), timeout=7200)  # Cache for 2 hours
        
        return trend

class ProductService:
    @staticmethod
    def get_recommended_products(user_id, limit=10):
        """Get product recommendations based on user behavior."""
        cache_key = f'recommended_products_{user_id}_{limit}'
        recommendations = cache.get(cache_key)
        
        if recommendations is None:
            # Get categories from user's previous orders
            user_categories = Category.objects.filter(
                product__orderitem__order__user_id=user_id
            ).distinct()
            
            # Get popular products from those categories
            recommendations = Product.objects.filter(
                category__in=user_categories,
                stock_quantity__gt=0
            ).annotate(
                popularity_score=Count('orderitem') + F('view_count') / 10
            ).exclude(
                # Exclude products user already bought
                orderitem__order__user_id=user_id
            ).order_by('-popularity_score')[:limit]
            
            cache.set(cache_key, list(recommendations), timeout=1800)  # 30 minutes
        
        return recommendations

# Step 5: Advanced caching utilities
# apps/core/utils/cache.py

from django.core.cache import cache
from django.conf import settings
import hashlib
import pickle
from functools import wraps

class CacheManager:
    """Advanced cache management utilities."""
    
    DEFAULT_TIMEOUT = getattr(settings, 'CACHE_TTL', 300)
    
    @classmethod
    def get_or_set(cls, key, callable_func, timeout=None):
        """Get from cache or execute function and cache result."""
        timeout = timeout or cls.DEFAULT_TIMEOUT
        result = cache.get(key)
        
        if result is None:
            result = callable_func()
            cache.set(key, result, timeout)
        
        return result
    
    @classmethod
    def invalidate_pattern(cls, pattern):
        """Invalidate all cache keys matching a pattern."""
        try:
            from django_redis import get_redis_connection
            redis_conn = get_redis_connection("default")
            keys = redis_conn.keys(f"*{pattern}*")
            if keys:
                redis_conn.delete(*keys)
                return len(keys)
        except ImportError:
            # Fallback for non-Redis cache backends
            pass
        return 0
    
    @classmethod
    def cache_key_from_args(cls, prefix, *args, **kwargs):
        """Generate cache key from function arguments."""
        key_data = f"{prefix}:{str(args)}:{str(sorted(kwargs.items()))}"
        return hashlib.md5(key_data.encode()).hexdigest()[:16]

def cached_result(timeout=None, key_prefix='cached'):
    """Decorator for caching function results."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = CacheManager.cache_key_from_args(
                f"{key_prefix}:{func.__name__}", *args, **kwargs
            )
            
            return CacheManager.get_or_set(
                cache_key, 
                lambda: func(*args, **kwargs),
                timeout
            )
        return wrapper
    return decorator

# Usage examples in views
# apps/ecommerce/views.py

from django.http import JsonResponse
from django.views.generic import ListView
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from .services import AnalyticsService, ProductService
from .models import Product

@method_decorator(cache_page(300), name='get')  # Cache for 5 minutes
class ProductListView(ListView):
    model = Product
    template_name = 'products/list.html'
    paginate_by = 20
    
    def get_queryset(self):
        return Product.objects.select_related('category').filter(
            stock_quantity__gt=0
        ).order_by('-created_at')

def analytics_dashboard(request):
    """API endpoint for analytics dashboard."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    # These service methods use internal caching
    product_report = AnalyticsService.get_product_performance_report()
    customer_segments = AnalyticsService.get_customer_segmentation()
    sales_trend = AnalyticsService.get_monthly_sales_trend()
    
    return JsonResponse({
        'product_performance': product_report[:10],  # Top 10
        'customer_segments': {
            segment['segment']: len([c for c in customer_segments if c['segment'] == segment['segment']])
            for segment in customer_segments
        },
        'sales_trend': sales_trend
    })

@cached_result(timeout=600, key_prefix='recommendations')
def get_user_recommendations(request, user_id):
    """Get cached product recommendations for user."""
    recommendations = ProductService.get_recommended_products(user_id)
    return JsonResponse({
        'recommendations': [
            {
                'id': p.id,
                'name': p.name,
                'price': str(p.price),
                'category': p.category.name
            }
            for p in recommendations
        ]
    })
```

#### Testing Your Implementation

```python
# tests/test_middleware.py
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from django.core.cache import cache
from apps.core.middleware.api_tracking import APITrackingMiddleware

class APITrackingMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = APITrackingMiddleware(lambda request: None)
    
    def test_api_usage_tracking(self):
        request = self.factory.get('/api/products/')
        request.user = User.objects.create_user('testuser')
        
        # Clear cache
        cache.clear()
        
        # Process request
        self.middleware(request)
        
        # Check if usage was tracked
        from django.utils import timezone
        today = timezone.now().date()
        cache_key = f"api_usage:{today}:/api/products/:GET"
        self.assertEqual(cache.get(cache_key), 1)

# tests/test_signals.py
from django.test import TestCase
from django.contrib.auth.models import User
from apps.ecommerce.models import UserProfile, AuditLog

class SignalTest(TestCase):
    def test_user_profile_creation(self):
        """Test that UserProfile is created when User is created."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        
        # Check if profile was created
        self.assertTrue(
            UserProfile.objects.filter(user=user).exists()
        )
    
    def test_audit_log_creation(self):
        """Test that audit log is created for user creation."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        
        # Check if audit log was created
        self.assertTrue(
            AuditLog.objects.filter(
                model_name='User',
                object_id=user.pk,
                action='created'
            ).exists()
        )

# tests/test_services.py
from django.test import TestCase
from django.contrib.auth.models import User
from apps.ecommerce.models import Product, Category, Order, OrderItem
from apps.ecommerce.services import AnalyticsService

class AnalyticsServiceTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser')
        self.category = Category.objects.create(name='Electronics', slug='electronics')
        self.product = Product.objects.create(
            name='Test Product',
            slug='test-product',
            category=self.category,
            price=100.00,
            stock_quantity=10
        )
    
    def test_product_performance_report(self):
        """Test product performance report generation."""
        # Create test order
        order = Order.objects.create(
            user=self.user,
            status='paid',
            total_amount=200.00
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            quantity=2,
            price=100.00
        )
        
        report = AnalyticsService.get_product_performance_report()
        self.assertTrue(len(report) > 0)
        
        product_data = next(
            (item for item in report if item['id'] == self.product.id), 
            None
        )
        self.assertIsNotNone(product_data)
        self.assertEqual(product_data['total_sold'], 2)
        self.assertEqual(float(product_data['total_revenue']), 200.00)
```

---

## Advanced Topics and Extensions

### 1. Asynchronous Signal Handling

```python
# Using Celery for background signal processing
from celery import shared_task
from django.db.models.signals import post_save
from django.dispatch import receiver

@shared_task
def send_welcome_email_task(user_id):
    """Background task for sending welcome email."""
    user = User.objects.get(pk=user_id)
    # Send email logic here
    pass

@shared_task
def update_analytics_task(model_name, object_id, action):
    """Background task for updating analytics."""
    # Update analytics logic here
    pass

@receiver(post_save, sender=User)
def user_created_async_handler(sender, instance, created, **kwargs):
    """Handle user creation with async tasks."""
    if created:
        # Queue background tasks
        send_welcome_email_task.delay(instance.id)
        update_analytics_task.delay('User', instance.id, 'created')
```

### 2. Advanced Cache Invalidation Strategies

```python
class SmartCacheManager:
    """Intelligent cache management with dependency tracking."""
    
    @classmethod
    def set_with_dependencies(cls, key, value, timeout, dependencies=None):
        """Set cache with dependency tracking."""
        cache.set(key, value, timeout)
        
        if dependencies:
            for dep in dependencies:
                dep_key = f"cache_deps:{dep}"
                dependent_keys = cache.get(dep_key, set())
                dependent_keys.add(key)
                cache.set(dep_key, dependent_keys, timeout * 2)
    
    @classmethod
    def invalidate_dependencies(cls, dependency):
        """Invalidate all caches dependent on a specific key."""
        dep_key = f"cache_deps:{dependency}"
        dependent_keys = cache.get(dep_key, set())
        
        if dependent_keys:
            cache.delete_many(list(dependent_keys))
            cache.delete(dep_key)

# Usage in models
class Product(models.Model):
    # ... fields ...
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Invalidate dependent caches
        SmartCacheManager.invalidate_dependencies(f'product:{self.pk}')
        SmartCacheManager.invalidate_dependencies(f'category:{self.category_id}')
```

### 3. Database Query Optimization Patterns

```python
class OptimizedQueryMixin:
    """Mixin for common query optimizations."""
    
    @classmethod
    def with_related_data(cls):
        """Pre-load related data to avoid N+1 queries."""
        return cls.objects.select_related().prefetch_related()
    
    @classmethod
    def active_only(cls):
        """Filter for active records only."""
        return cls.objects.filter(is_active=True)
    
    @classmethod
    def bulk_update_status(cls, ids, status):
        """Bulk update status for better performance."""
        return cls.objects.filter(id__in=ids).update(status=status)

# Advanced aggregation patterns
def get_advanced_product_metrics():
    """Get comprehensive product metrics with single query."""
    from django.db.models import (
        Count, Sum, Avg, StdDev, Variance,
        Window, F, Case, When
    )
    
    return Product.objects.annotate(
        # Sales metrics
        total_quantity_sold=Sum('orderitem__quantity'),
        total_revenue=Sum(F('orderitem__quantity') * F('orderitem__price')),
        unique_buyers=Count('orderitem__order__user', distinct=True),
        
        # Performance metrics
        avg_order_quantity=Avg('orderitem__quantity'),
        price_variance=Variance('orderitem__price'),
        
        # Ranking within category
        category_sales_rank=Window(
            expression=Rank(),
            partition_by=[F('category')],
            order_by=F('total_revenue').desc()
        ),
        
        # Status indicators
        performance_tier=Case(
            When(total_revenue__gte=10000, then=Value('Premium')),
            When(total_revenue__gte=5000, then=Value('Gold')),
            When(total_revenue__gte=1000, then=Value('Silver')),
            default=Value('Bronze'),
            output_field=CharField()
        )
    ).select_related('category')
```

This comprehensive lesson provides you with:

1. **Deep understanding** of Django's advanced features
2. **Practical examples** you can implement immediately  
3. **Best practices** for production applications
4. **Common pitfalls** to avoid
5. **Testing strategies** to ensure code quality
6. **Performance optimization** techniques
7. **Real-world patterns** used in enterprise applications

The combination of middleware, signals, advanced ORM techniques, and caching creates a powerful foundation for building scalable Django applications. Practice implementing these patterns in your own projects to master these advanced concepts!