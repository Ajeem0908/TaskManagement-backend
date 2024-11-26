# consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .mongo_models import Message, Users
import datetime

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get the room name from the URL
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'  # Group name based on room name

        # Join the room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        # Accept WebSocket connection
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        # Parse incoming message
        text_data_json = json.loads(text_data)
        sender_username = text_data_json['sender']
        receiver_username = text_data_json['receiver']
        message_content = text_data_json['message']
        file_data = text_data_json.get('file_data', None)  # Optional field
        timestamp = datetime.datetime.utcnow()

        # Fetch users
        sender = await self.get_user_by_username(sender_username)
        receiver = await self.get_user_by_username(receiver_username)

        # Create and save the message (without room_name)
        message = Message(
            sender=sender,
            receiver=receiver,
            message=message_content,
            timestamp=timestamp,
            file_data=file_data
        )
        message.save()

        # Broadcast message to the room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'sender': sender_username,
                'receiver': receiver_username,
                'message': message_content,
                'timestamp': timestamp.isoformat(),
                'file_data': file_data,
            }
        )

    async def chat_message(self, event):
        # Send the message to WebSocket
        await self.send(text_data=json.dumps(event))

    async def get_user_by_username(self, username):
        # Helper function to fetch the user by username
        return Users.objects(username=username).first()
