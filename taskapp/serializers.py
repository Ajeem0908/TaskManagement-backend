from rest_framework import serializers
import mongoengine as me
from mongoengine import Document, EmbeddedDocument
from .mongo_models import User, Task, Project, Tag, ActivityLog, Message
from datetime import datetime




class UserSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    username = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=['admin', 'manager', 'Designer', 'developer', 'Tester'])  
    gender = serializers.ChoiceField(choices=['Male', 'Female', 'Other'])
    phone_number = serializers.CharField(max_length=10)  
    status = serializers.ChoiceField(choices=['Active', 'Inactive'])  

    def create(self, validated_data):
        return User(**validated_data).save()

    # def update(self, instance, validated_data):
    #     for key, value in validated_data.items():
    #         setattr(instance, key, value)
    #     instance.save()
    #     return instance

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.password = validated_data.get('password', instance.password)
        instance.role = validated_data.get('role', instance.role)
        instance.save()
        return instance

class ProjectSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField(max_length=255)
    description = serializers.CharField()
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    created_by = UserSerializer(read_only=True)
    assigned_users = serializers.ListField(child=serializers.CharField())
    

    def get_assigned_users(self, obj):
        return [user.username for user in obj.assigned_users]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['created_by'] = str(instance.created_by.id) if instance.created_by else None
        representation['assigned_users'] = [
            {"id": str(user.id), "username": user.username} for user in instance.assigned_users
        ]
        return representation

    def validate(self, data):
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if end_date and start_date and end_date < start_date:
            raise serializers.ValidationError("End date must be after start date")
        return data 

class TaskSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    title = serializers.CharField(max_length=255)
    description = serializers.CharField()
    priority = serializers.CharField()
    status = serializers.CharField()
    due_date = serializers.DateField()
    created_at = serializers.DateField()
    updated_at = serializers.DateField()
    completed_at = serializers.DateField()
    # comment = serializers.CharField()

    def validate(self, data):
        due_date = data.get('due_date')
        completed_at = data.get('completed_at')
        if completed_at and completed_at < due_date:
            raise serializers.ValidationError("Completed date cannot be earlier than due date.")
        return data

class ActivityLogSerializer(serializers.Serializer):
    id = serializers.CharField()
    task = serializers.CharField()
    user = serializers.CharField()
    action = serializers.ChoiceField(choices=[('create', 'Create'), ('update', 'Update'), ('delete', 'Delete')])
    description = serializers.CharField()
    timestamp = serializers.DateTimeField()


class ChatRoomSerializer(serializers.Serializer):
    participants = UserSerializer(many=True)


class MessageSerializer(serializers.Serializer):
    chat_room = ChatRoomSerializer()
    sender = UserSerializer()
    receiver = UserSerializer()

    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'message', 'timestamp', 'is_read']



# serializers.py

from rest_framework import serializers
from .mongo_models import ChatSession


class ChatSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatSession
        fields = ['user1', 'user2', 'updated_on']
