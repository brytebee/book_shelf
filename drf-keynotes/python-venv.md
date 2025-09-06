# Create venv
py -m venv venv

# Activate it
venv\Scripts\activate

# Install packages
pip install django djangorestframework drf-spectacular

# Deactivate when done
deactivate

## NOTE

On Windows, use this command to create a Python virtual environment:

```bash
python -m venv venv_name
```

For example:
```bash
python -m venv myproject_env
```

## To activate it:
```bash
venv_name\Scripts\activate
```

## To deactivate:
```bash
deactivate
```

## Complete workflow:
```bash
# Create venv
python -m venv myproject_env

# Activate it
myproject_env\Scripts\activate

# Install packages
pip install django djangorestframework drf-spectacular

# Deactivate when done
deactivate
```

**Note:** If `python` doesn't work, try `py` instead:
```bash
py -m venv myproject_env
```