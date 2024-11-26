
from django.urls import path
from channels.routing import URLRouter
from channels.auth import AuthMiddlewareStack
from .consumers import ChatConsumer

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/chat-server/', consumers.ChatConsumer.as_asgi()),
]

# websocket_urlpatterns = [
#     path('ws/chat/', consumers.ChatConsumer.as_asgi()),
# ]
