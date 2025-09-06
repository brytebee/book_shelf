## Renaming Django Project and Global Updates

### Method 1: Rename Existing Project (Recommended for Small Projects)

#### 1. Rename Project Directory
```bash
# If you're inside the project
cd ..
mv my_project new_project_name
cd new_project_name
```

#### 2. Update Settings Module References
```python
# manage.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'new_project_name.settings')

# new_project_name/wsgi.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'new_project_name.settings')

# new_project_name/asgi.py  
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'new_project_name.settings')
```

#### 3. Rename Inner Project Folder
```bash
mv my_project new_project_name
```

#### 4. Update settings.py
```python
# new_project_name/settings.py
ROOT_URLCONF = 'new_project_name.urls'
WSGI_APPLICATION = 'new_project_name.wsgi.application'
```

### Method 2: Fresh Start with Migration (Recommended for Complex Projects)

#### 1. Create New Project
```bash
django-admin startproject new_project_name
cd new_project_name
```

#### 2. Copy Apps and Files
```bash
# Copy your custom apps
cp -r ../my_project/account ./
cp -r ../my_project/myapp ./

# Copy other important files
cp ../my_project/requirements.txt ./
cp ../my_project/.gitignore ./  # if exists
```

#### 3. Update settings.py
```python
# new_project_name/settings.py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'account',
    'myapp',
]

AUTH_USER_MODEL = 'account.User'
# ... rest of your settings
```

#### 4. Set Up Database
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### Method 3: Using django-admin Rename Command (Third-party)

#### 1. Install django-extensions
```bash
pip install django-extensions
```

#### 2. Add to settings
```python
INSTALLED_APPS = [
    # ... other apps
    'django_extensions',
]
```

#### 3. Use rename command
```bash
python manage.py rename_project new_project_name
```

### Global Updates Needed After Renaming

#### 1. Virtual Environment (if named after project)
```bash
deactivate
cd ..
mv venv new_project_venv  # or create new one
cd new_project_name
source ../new_project_venv/bin/activate  # macOS
# OR
..\new_project_venv\Scripts\activate  # Windows
```

#### 2. Git Repository
```bash
# Update remote if needed
git remote set-url origin https://github.com/username/new_project_name.git

# Update README.md, package.json, etc.
```

#### 3. IDE/Editor Configuration
- Update project name in VS Code settings
- Update PyCharm project configuration
- Update any launch configurations

#### 4. Deployment Settings
```bash
# Update any deployment scripts
# Update docker-compose.yml
# Update Heroku app name
# Update environment variables
```

#### 5. Documentation Updates
```markdown
# README.md
# Project Name: New Project Name

## Installation
git clone https://github.com/username/new_project_name.git
cd new_project_name
```

### Verification Steps

#### 1. Test Project Runs
```bash
python manage.py runserver
```

#### 2. Check All Imports Work
```bash
python manage.py check
```

#### 3. Test Database Operations
```bash
python manage.py shell
>>> from account.models import User
>>> User.objects.all()
```

#### 4. Verify URLs
```bash
# Test all your endpoints still work
curl http://127.0.0.1:8000/api/auth/profile/
```

### Quick Rename Script (Bash)

```bash
#!/bin/bash
OLD_NAME="my_project"
NEW_NAME="$1"

if [ -z "$NEW_NAME" ]; then
    echo "Usage: ./rename.sh new_project_name"
    exit 1
fi

# Rename files
find . -name "*.py" -type f -exec sed -i "s/$OLD_NAME/$NEW_NAME/g" {} \;

# Rename directory
mv $OLD_NAME $NEW_NAME

echo "Project renamed from $OLD_NAME to $NEW_NAME"
echo "Don't forget to update your virtual environment and git remote!"
```

### Best Practices

1. **Backup first**: Always backup your project before renaming
2. **Use Method 2** for production projects with data
3. **Update all references**: Check imports, URLs, and configurations  
4. **Test thoroughly**: Ensure all functionality works after rename
5. **Update documentation**: README, API docs, deployment guides

The fresh start method (Method 2) is often cleanest and safest for important projects!