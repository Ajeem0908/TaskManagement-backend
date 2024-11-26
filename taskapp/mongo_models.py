import mongoengine as me 
import re
from datetime import datetime
from datetime import date
from django.contrib.auth.models import User
from mongoengine import Document, DateTimeField,ReferenceField,ListField,StringField,BooleanField,ObjectIdField, StringField,FileField
from mongoengine import ValidationError
# from  import ChatRoom
import datetime , uuid 
from werkzeug.security import generate_password_hash, check_password_hash
from mongoengine import Document

class Users(Document):
    username = StringField(required=True)
    email = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, choices=['admin', 'manager', 'Designer', 'developer', 'tester'])
    gender = StringField(required=True, choices=['Male', 'Female', 'Other'])
    phone_number = StringField(required=True, validation=lambda number: Users.validate_phone_number(number))
    status = StringField(choices=['Active', 'Inactive'])


    @staticmethod
    def validate_phone_number(phone_number):
        """Validate that the phone number consists of 10 digits."""
        if not re.match(r'^\d{10}$', phone_number):
            raise ValidationError('Phone number must be exactly 10 digits.')
        
    def __str__(self):
        return self.username
    
    def set_password(self, raw_password):
        """Set the user's password to the hashed version of the raw password."""
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        """Check if the provided password matches the stored hashed password."""
        return check_password_hash(self.password, raw_password)

        
class Project(me.Document):
    name = me.StringField(required=True,unique=True)
    description = me.StringField(required=True)
    start_date = me.DateField(required=True)
    end_date = me.DateField(required=True)
    created_by = me.ReferenceField(Users, reverse_delete_rule=me.PULL)
    assigned_users = me.ListField(me.ReferenceField(Users))

    def __str__(self):
        return self.name
    

class Task(me.Document):
    PRIORITY_CHOICES = ['low', 'medium', 'high']
    STATUS_CHOICES = ['Open','in progress', 'Pending', 'Rejected', 'done']
    title = me.StringField(required=True)
    description = me.StringField(required=True)
    project = me.ReferenceField('Project', reverse_delete_rule=me.CASCADE)
    assigned_to = me.ReferenceField('Users', reverse_delete_rule=me.CASCADE)
    priority = me.StringField(choices=PRIORITY_CHOICES, required=True)
    status = me.StringField(choices=STATUS_CHOICES, required=True)
    due_date = me.DateField(required=True)
    created_at = me.DateField(default=date.today)  
    updated_at = me.DateField(default=date.today)  
    completed_at = me.DateField(null=True) 
    # comment= me.StringField()

    def save(self, *args, **kwargs):
        self.updated_at = date.today()  
        if not self.created_at:
            self.created_at = date.today()  

        if self.status == 'done' and not self.completed_at:
            self.completed_at = date.today()  
        super(Task, self).save(*args, **kwargs)

    def get_assigned_users(self):
        return Users.objects.filter(project=self.project)

    def __str__(self):
        return self.title

class Tag(me.Document):
    name = me.StringField(required=True, unique=True)
    tasks = me.ListField(me.ReferenceField(Task))

    def __str__(self):
        return self.name

class ActivityLog(me.Document):
    TASK_PROCESSING = 'processing'
    TASK_PENDING = 'pending'
    TASK_COMPLETED = 'completed'

    NOTIFICATION_REMINDER = 'reminder'
    NOTIFICATION_OVERDUE = 'overdue'
    
    ACTION_CHOICES = [
        (TASK_PROCESSING, 'Processing'),
        (TASK_PENDING, 'Pending'),
        (TASK_COMPLETED, 'Completed'),
        (NOTIFICATION_REMINDER, 'Reminder Sent'),
        (NOTIFICATION_OVERDUE, 'Overdue Notification Sent'),
    ]
    
    task = me.ReferenceField('Task', reverse_delete_rule=me.CASCADE)
    user = me.ReferenceField('Users', reverse_delete_rule=me.NULLIFY, null=True)
    action = me.StringField(choices=ACTION_CHOICES)
    description = me.StringField(required=True)
    timestamp = me.DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'ordering': ['-timestamp'],
        'indexes': [
            'task',
            ('task', 'action'),
        ],
    }




class Message(Document):
    sender = ReferenceField(Users, required=True, reverse_delete_rule='CASCADE', db_field='sender_id', verbose_name='Sender')
    receiver = ReferenceField(Users, required=True, reverse_delete_rule='CASCADE', db_field='receiver_id', verbose_name='Receiver')
    message = StringField(required=True, verbose_name='Message Content')
    timestamp = DateTimeField(default=datetime.datetime.utcnow, verbose_name='Time Sent')
    is_read = BooleanField(default=False, verbose_name='Read Status')
    file_data = StringField(verbose_name='File Data')
    id_sender = StringField()
   
    meta = {
        'collection': 'messages',  
        'ordering': ['-timestamp'],  
        'indexes': [
            'sender',  
            'receiver',  
            'timestamp'  
        ]
    }

    def __str__(self):
        return f'Message from {self.sender.username} to {self.receiver.username} at {self.timestamp}'

class ChatSession(Document):
    user1 = ObjectIdField(required=True)
    user2 = ObjectIdField(required=True)
    room_name = StringField(required=True)

    @staticmethod
    def get_or_create_room(sender_id, receiver_id):
        room_name = f"chat_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
        chat_session = ChatSession.objects(
            user1__in=[sender_id, receiver_id],
            user2__in=[sender_id, receiver_id]
        ).first()

        if not chat_session:
            chat_session = ChatSession(
                user1=min(sender_id, receiver_id),
                user2=max(sender_id, receiver_id),
                room_name=room_name
            )
            chat_session.save()
        
        return chat_session
    
    # class UserProfile(Document):
#     user_id = ReferenceField('User', required=True)  
#     is_online = BooleanField(default=False)


class Notification(me.Document):
    user_id = me.ReferenceField('Users', required=True)  # Reference to the User model
    message = me.StringField(required=True)  # Notification message
    link = me.StringField()  # Link related to the notification (optional)
    related_id = StringField(required=True)  # Add related_id field
    notification_type = StringField(required=True)
    is_read = me.BooleanField(default=False)  # Whether the notification is read
    created_at = me.DateTimeField(default=datetime.datetime.utcnow)
  

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message}"
    

from datetime import datetime, timedelta

class PasswordResetOTP(Document):
    email = StringField(required=True)
    otp = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    is_used = BooleanField(default=False)

  


class Comment(me.Document):
    content = me.StringField(required=True)
    name = me.StringField(required=True)
    task = me.ReferenceField('Task', reverse_delete_rule=me.CASCADE)
    project = ReferenceField('Project', required=True) 
    created_by = me.ReferenceField('Users', reverse_delete_rule=me.CASCADE)
    created_at = me.DateTimeField(default=date.today)
    file = me.StringField()

    

    meta = {
        'ordering': ['-created_at'],
        'indexes': [
            {'fields': ['task']},  
        ]
    }
class Reply(Document):
    content = StringField(required=True)
    name = me.StringField(required=True)
    comment = ReferenceField(Comment, required=True)  # Reference to the original comment
    created_at = StringField(default=str(datetime.utcnow()))  
    def __str__(self):
        return f"Reply to {self.comment.id}"

class Report(me.Document):
    report_type = me.StringField(
        required=True, 
        choices=['project_summary', 'user_activity', 'task_summary', 'notification_log']
    )
    generated_by = me.ReferenceField('Users', reverse_delete_rule=me.NULLIFY)  
    data = me.DictField(required=True)  # Stores report content dynamically
    created_at = me.DateTimeField(default=datetime.utcnow)  

    meta = {
        'collection': 'reports',
        'ordering': ['-created_at'],
        'indexes': [
            'report_type',
            'generated_by',
            'created_at',
        ]
    }

    def __str__(self):
        return f"{self.report_type} report by {self.generated_by.username} at {self.created_at}"
