from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
import jwt
from django.conf import settings

@database_sync_to_async
def get_user_from_jwt(token):
    # Import Django models here, after apps are loaded
    from django.contrib.auth import get_user_model
    from django.contrib.auth.models import AnonymousUser

    User = get_user_model()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        return User.objects.get(id=user_id)
    except Exception:
        return AnonymousUser()


class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        # Import AnonymousUser here as well
        from django.contrib.auth.models import AnonymousUser

        qs = parse_qs(scope["query_string"].decode())
        token = qs.get("token", [None])[0]

        # Set scope['user'] only after importing models
        scope["user"] = await get_user_from_jwt(token) if token else AnonymousUser()

        return await super().__call__(scope, receive, send)
