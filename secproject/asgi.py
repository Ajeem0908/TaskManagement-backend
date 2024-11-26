
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
from taskapp.consumers import ChatConsumer
import taskapp.routing   # Import your websocket URL patterns

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secproject.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(  # Handle WebSocket connections
        URLRouter(
           taskapp.routing.websocket_urlpatterns  # Use your websocket URL patterns here
        )
    ),
})
