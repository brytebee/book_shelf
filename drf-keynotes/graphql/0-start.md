Assuming the app is basically setup ATM:
- Install graphql specific libraries
```bash
  pip install graphene-django django-filter
```

- Add the line below to installed apps in your projects  `settings.py`
```py
 'graphene_django',
```

- Add the line below to the end of `settings.py`
```py
 # GraphQL Configuration
GRAPHENE = {
    'SCHEMA': 'crm.schema.schema'
}
```

- In your app(s), define a `schema.py` file, similar to the one below:

```py
# crm/schema.py
import graphene

class Query(graphene.ObjectType):
    # Simple hello field
    hello = graphene.String(default_value="Hello World!")

schema = graphene.Schema(query=Query)

```

- Update your project `urls.py`, similar to the one below:

```py
"""
URL configuration for alx_backend_graphql_crm project.

alx_backend_graphql_crm/urls.py
"""
from django.contrib import admin
from django.urls import path
from graphene_django.views import GraphQLView
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    # path('admin/', admin.site.urls),
    path('graphql/', csrf_exempt(GraphQLView.as_view(graphiql=True)))
]

```

- Now, you can make calls from any client or your browser as graphene provides a really cool web interface through `graphiql` as seen in the URL config above. This call is from `REST client` extension on `vscode`.

```py
### requests.http
### TEST GraphQL endpoint

http://localhost:8000/graphql/
Content-Type: application/json

{
  "query": "{ hello }"
}
```




