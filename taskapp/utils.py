# utils.py
from datetime import datetime


def parse_datetime(datetime_str):
    try:
        # ISO 8601 format with timezone
        return datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S%z')
    except ValueError:
        raise ValueError('Invalid date format for completed_at')

# taskapp/utils.py

# from taskapp.mongo_models import ChatRoom

# def get_or_create_chat_room(sender, receiver):
#     chat_room = ChatRoom.objects(participants__all=[sender, receiver]).first()
#     if not chat_room:
#         chat_room = ChatRoom(participants=[sender, receiver])
#         chat_room.save()
#     return chat_room


from .mongo_models import Notification
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

def create_notification(user, message, link=None):
    # Create a new notification
    notification = Notification(user=user, message=message, link=link)
    notification.save()  # Save to MongoDB

    # Prepare notification data for WebSocket
    notification_data = {
        'user_id': str(user.id),
        'message': message,
        'link': link,
        'is_read': notification.is_read,
        'created_at': notification.created_at.isoformat()
    }

    # Send notification to the appropriate group
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'notifications_{user.id}',
        {
            'type': 'send_notification',
            'notification': notification_data
        }
    )
# In your mongo_models.py or any other appropriate file
def get_room_name(sender_id, receiver_id):
    # Ensure the smaller ID comes first for consistency
    return f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"

# secproject/taskapp/tasks.py
from .utils import create_notification  # Import the correct function
# secproject/taskapp/utils.py
def send_notification(message):
    # Your notification logic here
    print(message)

from gridfs import GridFS
from mongoengine.connection import get_db

def upload_file_to_gridfs(file):
    """Upload a file to GridFS and return the file ID."""
    db = get_db()  # Get the MongoDB connection
    fs = GridFS(db)  # Initialize GridFS
    file_id = fs.put(file, filename=file.name)  # Upload file
    return str(file_id)  # Return the file ID as a string
