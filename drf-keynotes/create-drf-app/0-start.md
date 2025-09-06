## Windows & macOS Setup (DRF Project)

### 1. Prerequisites
```bash
# Install Python 3.8+ (both platforms)
python --version
```

### 2. Create Project
```bash
# Create directory
mkdir myproject && cd myproject

# Virtual environment
python -m venv venv

# Activate
# Windows:
venv\Scripts\activate # Running this command on Git Bash from windows might present errors as Git Bash mimics a unix-like shell.
OR
venv\Scripts\Activate.ps1

# macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install django djangorestframework
pip freeze > requirements.txt
```

### 4. Django Setup
```bash
# Create project
django-admin startproject [myproject] .

# Create app
python manage.py startapp [myapp]
```

### 5. Configure Settings
```python
# myproject/settings.py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third party apps & libraries
    'rest_framework',  # Add this

    # Local apps
    'myapp',          # Add this
]
```
If it's graphql, go through [Graphql-start](/drf-keynotes/graphql/0-start.md) before proceeding.

### 6. Run
```bash
python manage.py migrate
python manage.py runserver
```

Done! Access at `http://127.0.0.1:8000/`