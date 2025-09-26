# asgi.py
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from src.apps.websocket.middleware import JWTAuthMiddleware
from src.apps.websocket import routing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "src.settings")




application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JWTAuthMiddleware(
        URLRouter(routing.websocket_urlpatterns)
    ),
})
