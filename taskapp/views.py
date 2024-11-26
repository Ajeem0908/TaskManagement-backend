from django.shortcuts import render
from rest_framework.generics import RetrieveAPIView
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.decorators import api_view
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotAllowed,HttpResponseServerError
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
import json, datetime ,logging,uuid
# from .utils import log_error, log_info, log_debug
from datetime import datetime, date, timezone
now = datetime.now()  
date.today()
print(now)
from django.utils import timezone 
from datetime import datetime 
import mongoengine as me 
from bson import ObjectId
from mongoengine.errors import ValidationError
from mongoengine import DoesNotExist, NotUniqueError,errors
from .mongo_models import Project, Task, Users, Tag, ActivityLog, Message,ChatSession,Comment,Report,Reply
import mongoengine as me 
from django.shortcuts import render
from rest_framework.response import Response
from .serializers import  UserSerializer,TaskSerializer,ProjectSerializer,MessageSerializer, ChatRoomSerializer
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import generics
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate
from mongoengine.queryset.visitor import Q
from drf_yasg.utils import swagger_auto_schema
from rest_framework.permissions import AllowAny
logger = logging.getLogger(__name__)
from .serializers import ProjectSerializer, TaskSerializer, ActivityLogSerializer
from taskapp.mongo_models import User, Message
from rest_framework.permissions import IsAuthenticated

 


class SearchByCategoryAPIView(APIView):
    def get(self, request, category, query):
        if category not in ['tasks', 'projects', 'users']:
            return Response({"error": "Invalid category. Choose from 'tasks', 'projects', 'users'."}, status=400)

        if category == 'tasks':
            results = Task.objects.filter(
                Q(title__icontains=query) |
                Q(description__icontains=query) |
                Q(status__icontains=query)
            )
            serializer = TaskSerializer(results, many=True)

        elif category == 'projects':
            results = Project.objects.filter(
                Q(name__icontains=query) |
                Q(description__icontains=query)
            )
            serializer = ProjectSerializer(results, many=True)

        elif category == 'users':
            results = User.objects.filter(role__icontains=query)
            serializer = UserSerializer(results, many=True)

        return Response(serializer.data)
    
class TaskDetailByNameAPIView(generics.RetrieveAPIView):
    serializer_class = TaskSerializer
    lookup_field = 'name'  

    def get_queryset(self):
        name = self.kwargs['task_name'] 
        return Task.objects.filter(name=name)
    
class DashboardCountsView(APIView):
    def get(self, request):
        
        total_users = Users.objects.count()
        total_projects = Project.objects.count()
        total_tasks = Task.objects.count()
        total_tags = Tag.objects.count()
        total_activity_logs = ActivityLog.objects.count()

        total_designers = Users.objects.filter(role='Designer').count()
        total_developers = Users.objects.filter(role='developer').count()
        total_testers = Users.objects.filter(role='tester').count()

        counts = {
            "total_users": total_users,
            "total_projects": total_projects,
            "total_tasks": total_tasks,
            "total_tags": total_tags,
            "total_activity_logs": total_activity_logs,
            "total_designers": total_designers,
            "total_developers": total_developers,
            "total_testers": total_testers,
        }

        return Response(counts)

    def http_method_not_allowed(self, request, *args, **kwargs):
        return Response(
            {"detail": "Method Not Allowed. Only GET method is allowed."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )
    
import re
def search_users_chat(request):
    query = request.GET.get('query', '')

    if query:
      
        start_with_query = Users.objects.filter(username__istartswith=query)
        
        second_character_query = Users.objects.filter(username__iexact=f"{query[0]}{query[1]}") if len(query) > 1 else User.objects.none()
        
        users = list(start_with_query) + [user for user in second_character_query if user not in start_with_query]
        response_data = [
            {
                "user_id": str(user.id),  
                "username": user.username
            }
            for user in users
        ]

        return JsonResponse({"users": response_data}, status=200)

    return JsonResponse({"users": []}, status=200)



@csrf_exempt
def send_message(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            sender_id = data.get('sender_id')
            receiver_id = data.get('receiver_id')  
            message_content = data.get('message')
            file_data = data.get('file')
            id_sender = data.get('id_sender')
            print("id_sender", id_sender)

            # Validate message content
            if not message_content and not file_data:
                return JsonResponse({"error": "Message content or file must be provided."}, status=400)

            # Validate receiver existence
            try:
                receiver = Users.objects.get(id=receiver_id)
            except User.DoesNotExist:
                return JsonResponse({"error": "Receiver does not exist."}, status=400)

            try:
                sender = Users.objects.get(id=sender_id)
            except User.DoesNotExist:
                return JsonResponse({"error": "Sender does not exist."}, status=400)
            
            chat_session = ChatSession.get_or_create_room(sender_id, receiver_id)


            # Save the message
            message = Message(
                sender=sender,
                receiver=receiver,
                message=message_content,
                is_read=False,
                file_data=file_data,
                id_sender = id_sender,
            

            )
            message.save()


            return JsonResponse({
                "message": message_content,
                "message_id": str(message.id),
                "sender": str(sender.username),
                "receiver": str(receiver.username),
                "sender_role":sender.role,
                "receiver_role": receiver.role,
                "timestamp": message.timestamp.isoformat(),
                "file_data": message.file_data,
                "room_name": chat_session.room_name
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON."}, status=400)
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Only POST requests are allowed."}, status=405)

# @csrf_exempt
# def get_message(request):
#     if request.method == 'GET':
#         try:
#             sender_id = request.GET.get('sender_id')  
            
#             if not sender_id:
#                 return JsonResponse({"error": "sender_id is required."}, status=400)

#             try:
#                 sender = Users.objects.get(id=sender_id)
#             except DoesNotExist:
#                 return JsonResponse({"error": "Sender does not exist."}, status=400)

#             # Find all distinct receiver IDs from the messages sent by this sender
#             receiver_ids = Message.objects(sender=sender).distinct('receiver')

#             # Collect receiver info from the receiver IDs
#             receiver_info = []
#             for receiver_id in receiver_ids:
#                 try:
#                     receiver = User.objects.get(id=receiver_id)
#                     receiver_info.append({
#                         "receiver_id": str(receiver.id),
#                         "receiver_name": receiver.username
#                     })
#                 except Users.DoesNotExist:
#                     continue  # If receiver does not exist, skip

#             # Return the list of receivers the sender has communicated with
#             return JsonResponse({
#                 "sender_id": str(sender.id),
#                 "sender_name": sender.username,
#                 # "receiver_id":str(receiver.id),
#                 # "receiver_name": receiver.username,
#                 "receivers": receiver_info
#             }, status=200)

#         except Exception as e:
#             return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

#     # Return an error if request method is not GET
#     return JsonResponse({"error": "Only GET requests are allowed."}, status=405)



@csrf_exempt
def get_message(request):
    if request.method == 'GET':
        try:
            sender_id = request.GET.get('sender_id')  
            
            if not sender_id:
                return JsonResponse({"error": "sender_id is required."}, status=400)

            try:
                sender_id = ObjectId(sender_id)
            except Exception:
                return JsonResponse({"error": "Invalid sender_id format."}, status=400)

           
            try:
                sender = Users.objects.get(id=sender_id)
            except DoesNotExist:
                return JsonResponse({"error": "Sender does not exist."}, status=404)

            receiver_ids = Message.objects(sender=sender).distinct('receiver')

           
            receiver_info = []
            for receiver_id in receiver_ids:
                try:
                    receiver = Users.objects.get(id=receiver_id)  
                    receiver_info.append({
                        "receiver_id": str(receiver.id),
                        "receiver_name": receiver.username,
                        "sender_role":sender.role,
                        "receiver_role": receiver.role,
                    })
                except DoesNotExist:
                    continue 

            return JsonResponse({
                "sender_id": str(sender.id),
                "sender_name": sender.username,
                "receivers": receiver_info,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Only GET requests are allowed."}, status=405)

@csrf_exempt
def get_all_messages(request):
    if request.method == 'GET':
        try:
            # Retrieve all messages
            messages = Message.objects.all()
            # Collect message info
            message_info = []
            for message in messages:
                message_info.append({
                    "id": str(message.id),
                    "sender_id": str(message.sender.id),
                    "receiver_id": str(message.receiver.id),
                    "content": message.message,   # Adjust this based on your Message model fields
                    "timestamp": message.timestamp.isoformat(),  # Format timestamp as needed
                })

            return JsonResponse({
                "messages": message_info
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Only GET requests are allowed."}, status=405)


@csrf_exempt
def get_conversation(request):
    if request.method == 'GET':
        sender_id = request.GET.get('sender_id')
        receiver_id = request.GET.get('receiver_id')

        # Validate the presence of both sender_id and receiver_id
        if not sender_id or not receiver_id:
            return JsonResponse({"error": "Both sender_id and receiver_id are required."}, status=400)

        try:
            # Retrieve messages sent between the sender and receiver (both directions)
            messages = Message.objects.filter(
                (Q(sender=sender_id) & Q(receiver=receiver_id)) | 
                (Q(sender=receiver_id) & Q(receiver=sender_id))
            ).order_by('timestamp')

            # Convert messages to a list of dictionaries
            messages_data = [{
                "message_id": str(message.id),
                "sender": str(message.sender.username),
                "receiver": str(message.receiver.username),
                "message": message.message,
                "file_data": message.file_data,
                "timestamp": message.timestamp.isoformat(),
                "is_read": message.is_read,
                "sender_id": message.id_sender,
                # "receiver_id": receiver_id,
            } for message in messages]

            return JsonResponse({
                "messages": messages_data,
                # "sender_id": sender_id,
                # "receiver_id": receiver_id,
                "count": len(messages_data)
            }, status=200)

        except DoesNotExist:
            return JsonResponse({"error": "Sender or Receiver does not exist."}, status=404)
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Only GET requests are allowed."}, status=405)

@csrf_exempt
def delete_message(request):
    if request.method == 'DELETE':
        try:
            message_id = request.GET.get('message_id')
            delete_all = request.GET.get('delete_all', 'false').lower() == 'true'

           
            if not message_id:
                return JsonResponse({"error": "Required field: message_id is missing."}, status=400)

            try:
                message = Message.objects.get(id=message_id)

                if delete_all:
                    Message.objects.filter(sender=message.sender, receiver=message.receiver).delete()
                    return JsonResponse({"success": "All messages from this sender to this receiver have been deleted."}, status=200)
                else:
                    # Otherwise, delete the individual message
                    message.delete()
                    return JsonResponse({"success": "Message deleted successfully."}, status=200)

            except Message.DoesNotExist:
                return JsonResponse({"error": "Message not found."}, status=404)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    # Return an error if request method is not DELETE
    return JsonResponse({"error": "Only DELETE requests are allowed."}, status=405)


@csrf_exempt
def search_users(request, query):
    if request.method == 'GET':
        print("try")
        try:
            
            results = Users.objects(Q(username__icontains=query) | Q(email__icontains=query))
            print("result", results)

            # Prepare the response data
            user_list = [
                {
                    'id': str(user.id),  # Convert ObjectId to string if needed
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'gender': user.gender,
                    'phone_number': user.phone_number,
                    'status': user.status,
                }
                for user in results
            ]

            return JsonResponse({'users': user_list}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@swagger_auto_schema(method='post', request_body=UserSerializer)
@api_view(['POST'])
def register_manager(request):
    if request.method == 'POST':
        try:
            data = request.data
            
            default_username = 'manager123'
            default_email = 'manager@gmail.com'
            default_password = 'password'
            
            username = data.get('username', default_username)
            email = data.get('email', default_email)
            password = data.get('password', default_password)
        
            if username != default_username:
                return Response({'error': 'Username must be manager123'}, status=status.HTTP_400_BAD_REQUEST)
            
            if email != default_email:
                return Response({'error': 'Email must be manager@gmail.com'}, status=status.HTTP_400_BAD_REQUEST)
            
            
            if User.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            user = User(
                username=username,
                email=email,
                password=password,  
                role='manager',
                gender='N/A'
            )
            user.save()
            
            return Response({'message': 'Manager registered successfully'}, status=status.HTTP_201_CREATED)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON format'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
from mongoengine import signals       
from .signals import send_welcome_email
from allauth.socialaccount.models import SocialAccount
signals.post_save.connect(send_welcome_email, sender=User)

# @api_view(['POST'])
# @csrf_exempt
# def register_user(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)
#             if 'google_id' in data:
#                 google_id = data.get('google_id')
#                 email = data.get('email')

#                 # Check if Google user already exists
#                 if User.objects(email=email).count() > 0:
#                     return JsonResponse({'error': 'Google account already registered'}, status=400)

#                 # Create a new user using Google details
#                 user = User(
#                     username=email.split('@')[0],
#                     email=email,
#                     password=None,  # Password is not needed for Google sign-in users
#                     role='google_user',  # Assign a role if needed, or handle accordingly
#                     gender=None,  # You can modify this if gender info is available
#                     phone_number=None  # Set this if available through Google
#                 )
#                 user.save()

#                 # Optionally link with SocialAccount for Django-allauth
#                 SocialAccount.objects.create(user=user, uid=google_id, provider='google')

#                 return JsonResponse({'message': 'Google user created successfully'}, status=201)

       
            
#             required_fields = ['username', 'email', 'password', 'role', 'gender','phone_number']
#             errors = {}

#             for field in required_fields:
#                 if field not in data or not data[field]:
#                     errors[field] = f"{field} is required"

#             if errors:
#                 return JsonResponse({'errors': errors}, status=400)

#             username = data.get('username')
#             email = data.get('email')
#             password = data.get('password')
#             role = data.get('role')
#             gender = data.get('gender')
#             phone_number = data.get('phone_number') 
#             # status = data.get('status')  

#             if User.objects(username=username).count() > 0:
#                 return JsonResponse({'error': 'Username already exists'}, status=400)

#             if User.objects(email=email).count() > 0:
#                 return JsonResponse({'error': 'Email already exists'}, status=400)

#             if User.objects(phone_number=phone_number).count() > 0:
#                 return JsonResponse({'error': 'Phone number already exists'}, status=400)
            

#             user = User(
#                 username=username,
#                 email=email,
#                 password=password,
#                 role=role,
#                 gender=gender,
#                 phone_number=phone_number,  
#                 # status=status  
#             )
#             user.save()
            
#             return JsonResponse({'message': 'User created successfully'}, status=201)
#         except me.ValidationError as e:
#             return JsonResponse({'error': str(e)}, status=400)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)
#     return JsonResponse({'error': 'Invalid request method'}, status=400)

@api_view(['POST'])
@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            print(data)
            if 'google_id' in data:
                google_id = data.get('google_id')
                email = data.get('email')
            
                
                if Users.objects(email=email).count() > 0:
                    return JsonResponse({'error': 'Google account already registered'}, status=400)

                # Create a new user using Google details
                user = Users(
                    username=email.split('@')[0],
                    email=email,
                    password=None,  # Password is not needed for Google sign-in users
                    role='google_user',  # Assign a role if needed, or handle accordingly
                    gender=None,  # You can modify this if gender info is available
                    phone_number=None  # Set this if available through Google
                )
                user.save()

                SocialAccount.objects.create(user=user, uid=google_id, provider='google')

                return JsonResponse({'message': 'Google user created successfully'}, status=201)
            
            if 'facebook_email' in data:
                email = data.get('facebook_email')
                username = data.get('username')
                phone_number = data.get('phone_number')
                gender = data.get('gender')

                if Users.objects(email=email).count() > 0:
                    return JsonResponse({'error': 'Email already exists'}, status=400)

                user = Users(
                    username=username,
                    email=email,
                    password=None,  # No password for Facebook users
                    role='facebook_user',
                    gender=gender,
                    phone_number=phone_number
                )
                user.save()

                SocialAccount.objects.create(user=user, uid=email, provider='facebook')
                return JsonResponse({'message': 'Facebook user registered successfully'}, status=201)



            required_fields = ['username', 'email', 'password', 'role', 'gender', 'phone_number']
            errors = {}

            for field in required_fields:
                if field not in data or not data[field]:
                    errors[field] = f"{field} is required"

            if errors:
                return JsonResponse({'errors': errors}, status=400)

            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            gender = data.get('gender')
            phone_number = data.get('phone_number')

            # Check for unique fields
            # if Users.objects(username=username).count() > 0:
            #     return JsonResponse({'error': 'Username already exists'}, status=400)

            if Users.objects(email=email).count() > 0:
                return JsonResponse({'error': 'Email already exists'}, status=400)

            if Users.objects(phone_number=phone_number).count() > 0:
                return JsonResponse({'error': 'Phone number already exists'}, status=400)
            
            hashed_password = make_password(password)
            print("nnc")
            user = Users(
                username=username,
                email=email,
                password=hashed_password , 
                role=role,
                gender=gender,
                phone_number=phone_number,
            )
            user.save()
            
            return JsonResponse({'message': 'Register successfully'}, status=201)
        
        except ValidationError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)

def authenticate_user(username, password):
    user = authenticate(username=username, password=password)
    if user is not None:
        return user
    else:
        return None
  

def generate_tokens(user):
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return JsonResponse({'error': 'Username and password are required'}, status=400)

            try:
                user = Users.objects.get(username=username)
            except Users.DoesNotExist:
                return JsonResponse({'error': 'Invalid username'}, status=401)

            print(f"Attempting login for username: {username}")
            print(f"Stored password: {user.password}") 
            print(f"Entered password: {password}")  

            # First check using the check_password function
            if check_password(password, user.password):
                tokens = generate_tokens(user)
                return JsonResponse({
                    'message': 'Login successful',
                    'access': str(tokens.get('access')),
                    'refresh': str(tokens.get('refresh')),
                    'role': user.role,
                    'id': str(user.id),
                    'username': user.username,
                    'email': user.email,
                }, status=200)
            # Additional check comparing plain text password with the stored password
            elif user.password == password:
                print(f"Plain text password match for {username}")
                tokens = generate_tokens(user)
                return JsonResponse({
                    'message': 'Login successful (plain text match)',
                    'access': str(tokens.get('access')),
                    'refresh': str(tokens.get('refresh')),
                    'role': user.role,
                    'id': str(user.id),
                    'username': user.username,
                    'email': user.email,
                }, status=200)
            else:
                print(f"Password check failed for {username}: entered={password}, actual={user.password}")
                return JsonResponse({'error': 'Invalid password'}, status=401)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

class UserDetailView(RetrieveAPIView):
    queryset = Users.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'pk' 
    def get(self, request, *args, **kwargs):
        try:
            user = self.get_object()  
            serializer = self.get_serializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def users_view(request):
    if request.method == 'GET':
        users = Users.objects.all()  
        serializer = UserSerializer(users, many=True)  # Serialize the user data
        return Response(serializer.data, status=status.HTTP_200_OK)  # Return the serialized data


# @api_view(['GET'])
# def users_view(request):
#     if request.method == 'GET':
#         try:
#             users = User.objects()  # This should work if the User model is set up correctly
#             user_list = [{"username": user.username, "email": user.email} for user in users]
#             return JsonResponse({'users': user_list}, status=200)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

#     return JsonResponse({'error': 'Invalid request method'}, status=400)

def get_all_users(request):
    if request.method == 'GET':
        try:
            print("hhhc")
            users = Users.objects.all()
            user_count = users.count() 
            print(users)
            user_list = [
                {
                    'id': str(user.id),
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'password': user.password,
                    'gender':user.gender,
                    'phone_number':user.phone_number,
                    'status':user.status
                }
                for user in users
            ]
            return JsonResponse({'users': user_list, 'total_users': user_count}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def get_user_by_id(request,user_pk):
    if request.method == 'GET':
        try:
            if not ObjectId.is_valid(user_pk):
                return JsonResponse({'error': 'Invalid user ID format'}, status=400)

            user = Users.objects.get(id=ObjectId(user_pk))

            user_data = {
                'id': str(user.id),
                'username': user.username,
                'email': user.email,
                'role': user.role,  
                'password': user.password , 
                'gender':user.gender,
                'phone_number':user.phone_number,
                'status':user.status
            }
            
            return JsonResponse({'user': user_data}, status=200)
        
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)


from bson import ObjectId
@csrf_exempt
def edit_user(request, user_pk):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)

            try:
                user = Users.objects.get(id=ObjectId(user_pk))
            except Users.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            gender = data.get('gender')
            phone_number = data.get('phone_number')  
            status = data.get('status')  
    
            if phone_number:
                if Users.objects(phone_number=phone_number).filter(id__ne=user_pk).count() > 0:
                    return JsonResponse({'error': 'Phone number already exists.'}, status=400)

        
            if username:
                user.username = username
            if email:
                user.email = email
            if password:
                user.password = make_password(password)  
            if role:
                user.role = role
            if gender:
                user.gender = gender  
            if phone_number:  
                user.phone_number = phone_number
            if status: 
                user.status = status

            user.save()

            return JsonResponse({'message': 'User updated successfully'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except NotUniqueError:
            return JsonResponse({'error': 'A user with this username or email already exists.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def delete_user(request, user_pk):
    if request.method == 'DELETE':
        try:
            if not ObjectId.is_valid(user_pk):
                return JsonResponse({'error': 'Invalid user ID format'}, status=400)

            user = Users.objects.filter(id=ObjectId(user_pk)).first()
            if not user:
                return JsonResponse({'error': 'User not found'}, status=404)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


# Project Views
class ProjectCreateView(APIView):
    def post(self, request):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            project = serializer.save()
            start_date = serializer.validated_data['start_date']
            end_date = serializer.validated_data['end_date']
            return Response({
                "start_date": start_date.strftime('%Y-%m-%d'),
                "end_date": end_date.strftime('%Y-%m-%d'),
                "message": "Project created successfully!"
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
def create_project(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            required_fields = ['name', 'description', 'start_date', 'end_date', 'created_by', 'assigned_users']
            errors = {}

            
            for field in required_fields:
                if not data.get(field):
                    errors[field] = f'{field.replace("_", " ").capitalize()} is required'

            if errors:
                return JsonResponse({'error': errors}, status=400)

            start_date_str = data.get('start_date')
            end_date_str = data.get('end_date')
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            except ValueError:
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD'}, status=400)

            
            created_by_id = data.get('created_by')
            try:
                created_by = Users.objects.get(id=ObjectId(created_by_id))
            except (Users.DoesNotExist, ValueError):
                return JsonResponse({'error': 'Invalid created_by ObjectId or user not found'}, status=404)

            
            assigned_users_ids = data.get('assigned_users', [])
            assigned_users = []
            for user_id in assigned_users_ids:
                try:
                    user = Users.objects.get(id=ObjectId(user_id))
                    assigned_users.append(user)
                except (Users.DoesNotExist, ValueError):
                    errors[f'user_{user_id}'] = f'Invalid assigned_user ObjectId or user not found'

            if errors:
                return JsonResponse({'error': errors}, status=400)

            project = Project(
                name=data.get('name'),
                description=data.get('description'),
                start_date=start_date,
                end_date=end_date,
                created_by=created_by,
                assigned_users=assigned_users  
            )
            project.save()

            response_data = {
                'message': 'Project created successfully!',
                'id': str(project.id),
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date.strftime('%Y-%m-%d'),
                'end_date': project.end_date.strftime('%Y-%m-%d'),
                'created_by': {
                    'id': str(created_by.id),
                    'username': created_by.username
                },
                'assigned_users': [
                    {
                        'id': str(user.id),
                        'username': user.username,
                        'email': user.email
                    } for user in assigned_users
                ]
            }
             
            return JsonResponse(response_data)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseBadRequest("Invalid request method")



logger = logging.getLogger(__name__)

@csrf_exempt
def project_list_api(request):
    if request.method == 'GET':
        try:
            projects = Project.objects.all()
            project_count = projects.count()

            data = {
                'total_projects': project_count,
                'projects': []
            }

            logger.info(f"Number of projects retrieved: {project_count}")

            for project in projects:
                try:
                    created_by = project.created_by  
                    created_by_data = {
                        'id': str(created_by.id),
                        'username': getattr(created_by, 'username', 'manager143')
                    }
                except DoesNotExist:
                    logger.warning(f"User does not exist for project {project.id}")
                    created_by_data = {
                        'id': None,
                        'username': 'Unknown'
                    }

                assigned_users = project.assigned_users
                project_data = {
                    'id': str(project.id),
                    'name': project.name,
                    'description': project.description,
                    'start_date': project.start_date.strftime('%Y-%m-%d'),
                    'end_date': project.end_date.strftime('%Y-%m-%d'),
                    'created_by': created_by_data,
                    'assigned_users': [
                        {
                            'id': str(user.id),
                            'username': getattr(user, 'username', 'No username'),
                            'email': getattr(user, 'email', 'No email')
                        }
                        for user in assigned_users
                    ]
                }
                data['projects'].append(project_data)

            return JsonResponse(data, safe=False)

        except Exception as e:
            logger.error(f"Error in project_list_api: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'An error occurred', 'details': str(e)}, status=500)

@csrf_exempt
def project_detail_api(request, project_id):
    if request.method == 'GET':
        try:
            project = Project.objects.get(id=project_id)
            data = {
                'id': str(project.id),
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date,
                'end_date': project.end_date
            }
            return JsonResponse(data)
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project not found'}, status=404)
    return HttpResponseBadRequest("Invalid request method")



@csrf_exempt
def update_project(request, project_id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            
            try:
                project = Project.objects.get(id=project_id)
            except DoesNotExist:
                return JsonResponse({'error': 'Project not found'}, status=404)
            
            project.name = data.get('name', project.name)
            project.description = data.get('description', project.description)
            project.start_date = data.get('start_date', project.start_date)
            project.end_date = data.get('end_date', project.end_date)
            
            assigned_user_ids = data.get('assigned_users', [])
            if assigned_user_ids:
                try:
                    # Fetch the user documents based on the given IDs
                    assigned_users = Users.objects(id__in=assigned_user_ids)
                    if assigned_users:
                        project.assigned_users = assigned_users  # Replace existing users with new ones
                    else:
                        return JsonResponse({'error': 'No valid users found'}, status=400)
                except DoesNotExist:
                    return JsonResponse({'error': 'One or more users not found'}, status=400)
            
            # Save the updated project
            project.save()

            # Get updated assigned users' usernames
            assigned_usernames = [user.username for user in assigned_users]
            
            return JsonResponse({
                'message': 'Project updated successfully',
                'project': {
                    'id': str(project.id),
                    'name': project.name,
                    'description': project.description,
                    'start_date': str(project.start_date),
                    'end_date': str(project.end_date),
                    'assigned_users': assigned_usernames
                }
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return HttpResponseBadRequest("Invalid request method")



@csrf_exempt
def delete_project(request, project_id):
    if request.method == 'DELETE':
        try:
            project = Project.objects.get(id=project_id)
            project.delete()
            return JsonResponse({'message': 'Project deleted sucessfully'})
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return HttpResponseBadRequest("Invalid request method")



class TaskCreateView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        data.pop('created_at', None)
        data.pop('updated_at', None)

        serializer = TaskSerializer(data=data)
        if serializer.is_valid():
            task = serializer.save()
            return Response({'id': task.id}, status=status.HTTP_201_CREATED)
        
        return Response({'errors': serializer.errors, 'data': data}, status=status.HTTP_400_BAD_REQUEST)

# @csrf_exempt
# def create_task(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)

#             required_fields = ['title', 'due_date', 'project', 'assigned_to', 'description', 'completed_at']
#             errors = {}

#             for field in required_fields:
#                 if field not in data:
#                     errors[field] = f'{field.replace("_", " ").capitalize()} is required'

#             if errors:
#                 return JsonResponse({'error': errors}, status=400)

#             title = data['title']
#             due_date_str = data['due_date']
#             project_id = data['project']
#             assigned_to_id = data['assigned_to']
#             description = data.get('description', '')
#             priority = data.get('priority', 'medium')
#             status = data.get('status', 'in_progress')
#             completed_at_str = data.get('completed_at',None)
#             # created_at_str = data['created_at']

#             # try:
#             #     created_at = datetime.strptime(created_at_str, '%Y-%m-%d').date()  
#             # except ValueError:
#             #     return JsonResponse({'error': 'Invalid date format for created_at. Use YYYY-MM-DD'}, status=400)

#             try:
#                 due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
#             except ValueError:
#                 return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

           
#             completed_at = None
#             if completed_at_str:  # Check if there's a string provided
#                 if completed_at_str.strip():  # Check if it's not just whitespace
#                     try:
#                         completed_at = datetime.strptime(completed_at_str, '%Y-%m-%d')
#                     except ValueError:
#                         return JsonResponse({'error': 'Invalid date format for completed_at. Use YYYY-MM-DD'}, status=400)

#             try:
#                 project = Project.objects.get(id=project_id)
#                 assigned_to = Users.objects.get(id=assigned_to_id)

#                 if assigned_to.id not in [user.id for user in project.assigned_users]:
#                     return JsonResponse({'error': 'User is not assigned to this project'}, status=400)

#             except Project.DoesNotExist:
#                 return JsonResponse({'error': 'Project not found'}, status=404)
#             except Users.DoesNotExist:
#                 return JsonResponse({'error': 'User not found'}, status=404)

#             task = Task(
#                 title=title,
#                 description=description,
#                 project=project,
#                 assigned_to=assigned_to,
#                 priority=priority,
#                 status=status,
#                 due_date=due_date,
#                 # created_at=created_at,
#                 completed_at=completed_at
#             )
#             task.save()

#             return JsonResponse({
#                 'message': 'Task created successfully',
#                 'id': str(task.id),
#                 'project_name': project.name,
#                 'assigned_to_username': assigned_to.username,
#                 'completed_at': task.completed_at.strftime('%Y-%m-%d') if task.completed_at else None
#             }, status=201)

#         except json.JSONDecodeError:
#             return JsonResponse({'error': 'Invalid JSON'}, status=400)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)
    
#     return HttpResponseBadRequest("Invalid request method")


import json
from datetime import datetime, date
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from .mongo_models import Task, Project, Users 

@csrf_exempt
def create_task(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            required_fields = ['title', 'due_date', 'project', 'assigned_to', 'description', 'completed_at']
            errors = {}
            for field in required_fields:
                if field not in data:
                    errors[field] = f'{field.replace("_", " ").capitalize()} is required'

            if errors:
                return JsonResponse({'error': errors}, status=400)

            title = data['title']
            due_date_str = data['due_date']
            project_id = data['project']
            assigned_to_id = data['assigned_to']
            description = data.get('description', '')
            priority = data.get('priority', 'medium')
            status = data.get('status', 'Open')
            completed_at_str = data.get('completed_at', None)

            # Validate due_date
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            except ValueError:
                return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

            # Handle completed_at field
            completed_at = None
            if completed_at_str:
                if completed_at_str.strip():
                    try:
                        completed_at = datetime.strptime(completed_at_str, '%Y-%m-%d').date()
                    except ValueError:
                        return JsonResponse({'error': 'Invalid date format for completed_at. Use YYYY-MM-DD'}, status=400)

            try:
                print("try")
                project = Project.objects.get(id=project_id)
                assigned_to = Users.objects.get(id=assigned_to_id)
                print(project.assigned_users, assigned_to.id)
                # If assigned_users is a list of user IDs, use this check:
                if assigned_to.id not in [user.id for user in project.assigned_users]:  # Use list comprehension
                    return JsonResponse({'error': 'User is not assigned to this project'}, status=400)

            except Project.DoesNotExist:
                return JsonResponse({'error': 'Project not found'}, status=404)
            except Users.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

            task = Task(
                title=title,
                description=description,
                project=project,
                assigned_to=assigned_to,
                priority=priority,
                status=status,
                due_date=due_date,
                completed_at=completed_at
            )
            task.save()

            return JsonResponse({
                'message': 'Task created successfully',
                'id': str(task.id),
                'project_name': project.name,
                'assigned_to_username': assigned_to.username,
                'status': task.status,
                'due_date': task.due_date,
                'priority': task.priority,
                'description': task.description,
                # 'comment': task.comment,
                'completed_at': task.completed_at.strftime('%Y-%m-%d') if task.completed_at else None
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseBadRequest("Invalid request method")



# @csrf_exempt
# def create_task(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)

#             required_fields = ['title', 'due_date', 'project', 'assigned_to', 'description', 'completed_at']
#             errors = {} 
#             for field in required_fields:
#                 if field not in data:
#                     errors[field] = f'{field.replace("_", " ").capitalize()} is required'

#             if errors:
#                 return JsonResponse({'error': errors}, status=400)

#             title = data['title']
#             due_date_str = data['due_date']
#             project_id = data['project']
#             assigned_to_id = data['assigned_to']
#             description = data.get('description', '')
#             priority = data.get('priority', 'medium')
#             status = data.get('status', 'Open')
#             completed_at_str = data.get('completed_at', None)
            

#             # Validate due_date
#             try:
#                 # Correctly parse due_date string to a date object
#                 due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
#             except ValueError:
#                 return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

#             # Handle completed_at field
#             completed_at = None
#             if completed_at_str:  # If completed_at_str is provided
#                 if completed_at_str.strip():  # Check if it's not just whitespace
#                     try:
#                         # Correctly parse completed_at string to a date object
#                         completed_at = datetime.strptime(completed_at_str, '%Y-%m-%d').date()
#                     except ValueError:
#                         return JsonResponse({'error': 'Invalid date format for completed_at. Use YYYY-MM-DD'}, status=400)
#             try:
#                 project = Project.objects.get(id=project_id)
#                 assigned_to = Users.objects.get(id=assigned_to_id)

#                 if not any(user['id'] == assigned_to_id for user in project.assigned_users):
#                     return JsonResponse({'error': 'User is not assigned to this project'}, status=400)

#             except Project.DoesNotExist:
#                 return JsonResponse({'error': 'Project not found'}, status=404)
#             except Users.DoesNotExist:
#                 return JsonResponse({'error': 'User not found'}, status=404)

#             task = Task(
#                 title=title,
#                 description=description,
#                 project=project,
#                 assigned_to=assigned_to,
#                 priority=priority,
#                 status=status,
#                 due_date=due_date,
#                 completed_at=completed_at
#             )
#             task.save()

#             return JsonResponse({
#                 'message': 'Task created successfully',
#                 'id': str(task.id),
#                 'project_name': project.name,
#                 'assigned_to_username': assigned_to.username,
#                 'status': task.status,
#                 'due_date': task.due_date,
#                 'priority': task.priority,
#                 'description': task.description,
#                 'comment': task.comment,
#                 'completed_at': task.completed_at.strftime('%Y-%m-%d') if task.completed_at else None
#             }, status=201)

#         except json.JSONDecodeError:
#             return JsonResponse({'error': 'Invalid JSON'}, status=400)
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

#     return HttpResponseBadRequest("Invalid request method")



@csrf_exempt
def task_list_api(request):
    if request.method == 'GET':
        tasks = Task.objects.all()
        task_count = tasks.count()  

        data = {
            'total_tasks': task_count,
            'tasks': [
                {
                    'id': str(task.id),
                    'title': task.title,
                    'description': task.description,
                    'project': str(task.project.id) if task.project else None,
                    'assigned_to': {
                        'id': str(task.assigned_to.id) if task.assigned_to else None,
                        'username': task.assigned_to.username if task.assigned_to else None
                    },
                    'priority': task.priority,
                    'status': task.status,
                    'due_date': task.due_date,
                    'created_at': task.created_at.isoformat(),
                    'updated_at': task.updated_at.isoformat(),
                    'completed_at': task.completed_at.isoformat() if task.completed_at else None
                }
                for task in tasks
            ]
        }
        return JsonResponse(data, safe=False)
    
    return HttpResponseBadRequest("Invalid request method")

@csrf_exempt
def task_detail_api(request, task_name):
    if request.method == 'GET':
        try:
            task = Task.objects.get(title=task_name)
            data = {
                'id': str(task.id),
                'title': task.title,
                'description': task.description,
                'project': str(task.project.id) if task.project else None,
                'assigned_to': str(task.assigned_to.id) if task.assigned_to else None,
                'priority': task.priority,
                'status': task.status,
                'due_date': task.due_date,
                'created_at': task.created_at,
                'updated_at': task.updated_at,
                'completed_at': task.completed_at
            }
            return JsonResponse(data)
        except Task.DoesNotExist:
            return JsonResponse({'error': 'Task not found'}, status=404)
    return HttpResponseBadRequest("Invalid request method")




logger = logging.getLogger(__name__)
import logging

# @csrf_exempt
# def update_task(request, task_id):
#     if request.method == 'PUT':
#         try:
#             logger.info(f"Datetime module being used: {datetime}")
#             data = json.loads(request.body)
#             task = Task.objects.get(id=task_id)

#             task.title = data.get('title', task.title)
#             task.description = data.get('description', task.description)

#             if data.get('project'):
#                 task.project = Project.objects.get(id=data['project'])
#             elif task.project is None:
#                 return JsonResponse({'error': 'Task has no project and no project was provided'}, status=400)

#             if data.get('assigned_to'):
#                 task.assigned_to = Users.objects.get(id=data['assigned_to'])
#             elif task.assigned_to is None:
#                 return JsonResponse({'error': 'Task has no assigned user and no user was provided'}, status=400)

#             task.priority = data.get('priority', task.priority)

#             if 'due_date' in data:
#                 try:
#                     logger.info(f"Parsing due date: {data['due_date']}")
#                     task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d')
#                 except ValueError:
#                     return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

#             if data.get('status') == 'done' and task.status != 'done':
#                 task.completed_at = datetime.now()
#             elif data.get('status') != 'done':
#                 task.completed_at = None

#             task.status = data.get('status', task.status)
#             task.save()

#             return JsonResponse({
#                 'message': 'Task updated',
#                 'id': str(task.id),
#                 'completed_at': task.completed_at.strftime('%Y-%m-%d') if task.completed_at else None
#             })

#         except Task.DoesNotExist:
#             return JsonResponse({'error': 'Task not found'}, status=404)
#         except Project.DoesNotExist:
#             return JsonResponse({'error': 'Project not found'}, status=404)
#         except User.DoesNotExist:
#             return JsonResponse({'error': 'User not found'}, status=404)
#         except Exception as e:
#             logger.error(f"Exception occurred: {str(e)}")
#             return JsonResponse({'error': str(e)}, status=400)

#     return HttpResponseBadRequest("Invalid request method")

from datetime import datetime
print(datetime)
import json
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from .mongo_models import Task, Project, Users  
import logging

logger = logging.getLogger(__name__)    
print(datetime.strptime('2024-10-18', '%Y-%m-%d'))

@csrf_exempt
def update_task(request, task_id):
    if request.method == 'PUT':
        try:
            logger.info(f"Datetime module being used: {datetime}")
            data = json.loads(request.body)
            task = Task.objects.get(id=task_id)

          
            task.title = data.get('title', task.title)
            task.description = data.get('description', task.description)

            if data.get('project'):
                task.project = Project.objects.get(id=data['project'])
            elif task.project is None:
                return JsonResponse({'error': 'Task has no project and no project was provided'}, status=400)

            if data.get('assigned_to'):
                task.assigned_to = Users.objects.get(id=data['assigned_to'])
            elif task.assigned_to is None:
                return JsonResponse({'error': 'Task has no assigned user and no user was provided'}, status=400)

            task.priority = data.get('priority', task.priority)

            if 'due_date' in data:
                try:
                    task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d')
                except ValueError:
                    return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

            if data.get('status') == 'done' and task.status != 'done': 
                task.completed_at = datetime.now()
                print("done")
            elif data.get('status') != 'done':  
             task.completed_at = None
             task.status = data.get('status', task.status)
             task.save()

            return JsonResponse({
                'message': 'Task updated',
                'id': str(task.id),
                'completed_at': task.completed_at.strftime('%Y-%m-%d') if task.completed_at else None
            })

        except Task.DoesNotExist:
            return JsonResponse({'error': 'Task not found'}, status=404)
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project not found'}, status=404)
        except Users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            logger.error(f"Exception occurred: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseBadRequest("Invalid request method")


# from datetime import datetime
# import logging

# logger = logging.getLogger(__name__)

# # Test function to check datetime usage
# def test_datetime():
#     try:
#         test_date = '2024-09-27'
#         parsed_date = datetime.strptime(test_date, '%Y-%m-%d')
#         logger.info(f"Parsed date: {parsed_date}")
#         return True
#     except Exception as e:
#         logger.error(f"Exception during datetime parsing: {str(e)}")
#         return str(e)
    
# from datetime import datetime
# import json
# import logging
# from django.http import JsonResponse, HttpResponseBadRequest
# from django.views.decorators.csrf import csrf_exempt

# logger = logging.getLogger(__name__)

# @csrf_exempt
# def update_task(request, task_id):
#     if request.method == 'PUT':
#         try:
#             logger.info(f"Datetime module being used: {datetime}")
#             data = json.loads(request.body)
#             task = Task.objects.get(id=task_id)

#             # Update task fields
#             task.title = data.get('title', task.title)
#             task.description = data.get('description', task.description)

#             # Example of handling due_date field
#             if 'due_date' in data:
#                 try:
#                     logger.info(f"Parsing due date: {data['due_date']}")
#                     task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d')
#                 except ValueError:
#                     return JsonResponse({'error': 'Invalid date format for due_date. Use YYYY-MM-DD'}, status=400)

#             task.save()

#             return JsonResponse({
#                 'message': 'Task updated',
#                 'id': str(task.id)
#             })

#         except Task.DoesNotExist:
#             return JsonResponse({'error': 'Task not found'}, status=404)
#         except Exception as e:
#             logger.error(f"Exception occurred: {str(e)}")
#             return JsonResponse({'error': str(e)}, status=400)

#     return HttpResponseBadRequest("Invalid request method")



@csrf_exempt
def delete_task(request, task_id):
    if request.method == 'DELETE':
        try:
            task = Task.objects.get(id=task_id)
            task.delete()
            return JsonResponse({'message': 'Task deleted'})
        except Task.DoesNotExist:
            return JsonResponse({'error': 'Task not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return HttpResponseBadRequest("Invalid request method")

# Tag Views
from bson import ObjectId
from bson.errors import InvalidId
@csrf_exempt
def create_tag(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            name = data.get('name') 
            tasks_ids = data.get('tasks', [])
            
            if not name:
                return JsonResponse({'error': 'Name is required'}, status=400)
            
            if not tasks_ids:
                return JsonResponse({'error': 'At least one task ID is required'}, status=400)
            
            tasks = []
            for task_id in tasks_ids:  
                try:
                    ObjectId(task_id)
                    task = Task.objects.get(id=task_id)
                    tasks.append(task)
                except Task.DoesNotExist:
                    return JsonResponse({'error': f'Task with ID {task_id} not found'}, status=404)
                
                if Tag.objects(name=name).first():
                    return JsonResponse({'error': f'Tag with name "{name}" already exists'}, status=400)
            
            tag = Tag(
                name=name,
                tasks=tasks
            )
            tag.save()

            return JsonResponse({'message': 'Tag created', 'id': str(tag.id)}, status=201)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            print(Exception)
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)    

 

@csrf_exempt
def tag_list_api(request):
    if request.method == 'GET':
        try:
            tags = Tag.objects.all()
            tag_count = tags.count()  
            
            tags_data = []
            for tag in tags:
                tasks = tag.tasks.all() if hasattr(tag.tasks, 'all') else tag.tasks 
                tags_data.append({
                    'id': str(tag.id),
                    'name': tag.name,
                    'tasks': [str(task.id) for task in tasks]  
                })
                
            return JsonResponse({'total_tags': tag_count, 'tags': tags_data}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def tag_detail_api(request, tag_id):
    if request.method == 'GET':
        try:
            tag = Tag.objects.get(id=tag_id)
            data = {
                'id': str(tag.id),
                'name': tag.name,
                'tasks': [str(task.id) for task in tag.tasks]
            }
            return JsonResponse(data)
        except Tag.DoesNotExist:
            return JsonResponse({'error': 'Tag not found'}, status=404)
    return HttpResponseBadRequest("Invalid request method")

@csrf_exempt
def update_tag(request, tag_name):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            tag = Tag.objects.get(name =tag_name)  
            tag.name = data.get('name', tag.name)
            tasks_ids = data.get('tasks', [])
            tag.tasks = [Task.objects.get(id=task_id) for task_id in tasks_ids]
            tag.save()
            return JsonResponse({'message': 'Tag updated'})
        except Tag.DoesNotExist:
            return JsonResponse({'error': 'Tag not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return HttpResponseBadRequest("Invalid request method")


@csrf_exempt
def delete_tag(request, tag_name):
    if request.method == 'DELETE':
        try:
           
            tag = Tag.objects.get(name=tag_name)     
            tag.delete()
            return JsonResponse({'message': f'Tag "{tag_name}" deleted'}, status=200)
        except Tag.DoesNotExist:
            return JsonResponse({'error': f'Tag with name "{tag_name}" not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
            
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def create_activity_log(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            required_fields = ['action', 'description', 'task_id', 'user_id']
            errors = {}
            for field in required_fields:
                if not data.get(field):
                    errors[field] = f'{field} is a required field'

            if errors:
                return JsonResponse(errors, status=400)

            # Extract data from the request
            action = data.get('action')
            description = data.get('description')
            task_id = data.get('task_id')
            user_id = data.get('user_id')

            try:
                task = Task.objects.get(id=task_id)
            except Task.DoesNotExist:
                return JsonResponse({'task_id': f'Task with ID {task_id} not found'}, status=404)

            if str(task.assigned_to.id) != user_id:
                return JsonResponse({'error': 'User is not assigned to this task'}, status=403)

            # Create and save the activity log
            activity_log = ActivityLog(
                action=action,
                description=description,
                task=task,
                user=user_id,  
                timestamp=datetime.utcnow()
            )
            activity_log.save()

            return JsonResponse({'message': 'Activity log created', 'id': str(activity_log.id)}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseNotAllowed(['POST'], 'Invalid request method')

@csrf_exempt
def get_activity_logs(request):
    if request.method == 'GET':
        try:
            log_id = request.GET.get('id')
            if log_id:
                try:
                    activity_log = ActivityLog.objects.get(id=log_id)
                    task_id = str(activity_log.task.id) if activity_log.task else None
                    task_title = activity_log.task.title if activity_log.task else None
                    user_id = str(activity_log.user.id) if activity_log.user else None
                    user_username = activity_log.user.username if activity_log.user else None

                    log_data = {
                        'id': str(activity_log.id),
                        'action': activity_log.action,
                        'description': activity_log.description,
                        'task_id': task_id, 
                        'task': task_title, 
                        'user_id': user_id,  
                        'user': user_username,  
                        'timestamp': activity_log.timestamp.isoformat()
                    }
                    return JsonResponse({'log': log_data}, status=200)
                except ActivityLog.DoesNotExist:
                    return JsonResponse({'error': 'Activity log not found'}, status=404)
                
            else:
                
                logs = ActivityLog.objects.all()
                log_count = logs.count()
            logs_data = [
                {
                    'id': str(log.id),
                    'action': log.action,
                    'description': log.description,
                    'task_id': str(log.task.id) if log.task else None, 
                    'task': log.task.title if log.task else None,  
                    'user_id': str(log.user.id) if log.user else None,
                    'user': log.user.username if log.user else None, 
                    'timestamp': log.timestamp.isoformat()
                }
                for log in logs
            ]
            return JsonResponse({'logs': logs_data}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return HttpResponseNotAllowed(['GET'], 'Invalid request method')
    
@csrf_exempt
def delete_activity_log(request, log_id):
    if request.method == 'DELETE':
        try:
            activity_log = ActivityLog.objects.get(id=log_id)
            activity_log.delete()
            return JsonResponse({'message': 'Activity log deleted'}, status=204)  

        except ActivityLog.DoesNotExist:
            return JsonResponse({'error': 'Activity log not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseBadRequest("Invalid request method")

@csrf_exempt
def update_activity_log(request, log_id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            try:
                activity_log = ActivityLog.objects.get(id=log_id)
            except ActivityLog.DoesNotExist:
                return JsonResponse({'error': 'Activity log not found'}, status=404)

            action = data.get('action')
            description = data.get('description')
            task_id = data.get('task_id')
            user_id = data.get('user_id')

            if action is not None:
                activity_log.action = action
            if description is not None:
                activity_log.description = description
            if task_id is not None:
                try:
                    task = Task.objects.get(id=task_id)
                    activity_log.task = task
                except Task.DoesNotExist:
                    return JsonResponse({'task_id': f'Task with ID {task_id} not found'}, status=404)
            if user_id is not None:
                try:
                    user = User.objects.get(id=user_id)
                    activity_log.user = user
                except User.DoesNotExist:
                    return JsonResponse({'user_id': f'User with ID {user_id} not found'}, status=404)
                except ValueError:
                    return JsonResponse({'error': 'Invalid timestamp format'}, status=400)

            activity_log.save()

            return JsonResponse({'message': 'Activity log updated', 'id': str(activity_log.id)}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseNotAllowed(['PUT'], 'Invalid request method')


# @api_view(['GET'])
# def get_all_detail(request, user_id):
#     try:
#         if not ObjectId.is_valid(user_id):
#             return Response({'error': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)

#         user_id = ObjectId(user_id)
#         projects = Project.objects.filter(assigned_users=user_id)
#         tasks = Task.objects.filter(assigned_to=user_id)
#         activity_logs = ActivityLog.objects.filter(user=user_id)
#         project_serializer = ProjectSerializer(projects, many=True)
#         task_serializer = TaskSerializer(tasks, many=True)
#         activity_log_serializer = ActivityLogSerializer(activity_logs, many=True)

#         # Combine all data in the response
#         return Response({
#             'projects': project_serializer.data,
#             'tasks': task_serializer.data,
#             'activity_logs': activity_log_serializer.data

#         }, status=status.HTTP_200_OK)

#     except (ValidationError, DoesNotExist):
#         return Response({'error': 'Invalid or non-existent ObjectId'}, status=status.HTTP_400_BAD_REQUEST)
#     except Exception as e:
#         return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_all_detail(request, user_id):
    try:
        if not ObjectId.is_valid(user_id):
            return Response({'error': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)

        user_id = ObjectId(user_id)

        # Fetch related data
        projects = Project.objects.filter(assigned_users=user_id)
        tasks = Task.objects.filter(assigned_to=user_id)
        activity_logs = ActivityLog.objects.filter(user=user_id)

        # Serialize data
        project_serializer = ProjectSerializer(projects, many=True)
        task_serializer = TaskSerializer(tasks, many=True)
        activity_log_serializer = ActivityLogSerializer(activity_logs, many=True)

        # Combine all data in the response
        return Response({
            'projects': project_serializer.data,
            'tasks': task_serializer.data,
            'activity_logs': activity_log_serializer.data
        }, status=status.HTTP_200_OK)

    except ValidationError:
        return Response({'error': 'Invalid ObjectId'}, status=status.HTTP_400_BAD_REQUEST)
    except Task.DoesNotExist:
        return Response({'error': 'Task not found'}, status=status.HTTP_404_NOT_FOUND)
    except Project.DoesNotExist:
        return Response({'error': 'Project not found'}, status=status.HTTP_404_NOT_FOUND)
    except ActivityLog.DoesNotExist:
        return Response({'error': 'Activity log not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
 

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .mongo_models import Notification  

@csrf_exempt
def create_notification_log(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            required_fields = ['notification_type', 'message', 'related_id', 'user_id']
            errors = {}
            for field in required_fields:
                if not data.get(field):
                    errors[field] = f'{field} is a required field'

            if errors:
                return JsonResponse({'error': errors}, status=400)

           
            notification_type = data.get('notification_type')
            message = data.get('message')
            related_id = data.get('related_id')
            user_id = data.get('user_id')

           
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

            # Create and save the notification
            notification = Notification(
                user=user,
                notification_type=notification_type,  # Add notification_type
                message=message,
                related_id=related_id,  # Add related_id
                is_read=False
            )
            notification.save()

            return JsonResponse({'message': 'Notification created successfully', 'id': str(notification.id)}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return HttpResponseNotAllowed(['POST'], 'Invalid request method')

@csrf_exempt
def send_message_notification(request):
    if request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            
            required_fields = ['user_id', 'message', 'related_id']
            errors = {}
            
            for field in required_fields:
                if field not in data:
                    errors[field] = f'{field} is required'
            
            if errors:
                return JsonResponse({'error': errors}, status=400)

            user_id = data['user_id']
            message = data['message']
            related_id = data['related_id']
            
            # Create the notification
            notification = Notification(
                user_id=user_id,
                message=message,
                notification_type='message_received',  # Set type to message notification
                related_id=related_id
            )
            notification.save()
            
            return JsonResponse({
                'message': 'Message notification sent successfully',
                'id': str(notification.id)
            }, status=201)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)



import random
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from .mongo_models import PasswordResetOTP 



def send_otp(email):
    """Generate and send OTP to the email."""
    otp = str(random.randint(100000, 999999)) 
    try:
        send_mail(
            'Your Password Reset OTP',
            f'Your OTP is {otp}. Use this to reset your password.',
           'Task Management <kitecareer2018@gmail.com>', 
            [email],
            fail_silently=False,
        )
        print(f"OTP sent successfully to {email}.")  
    except Exception as e:
        print(f"Error sending email: {str(e)}")  
    return otp


@csrf_exempt
def forgot_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            email = data.get('email')

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            try:
                user = Users.objects.get(email=email)  
            except Users.DoesNotExist:
                return JsonResponse({'error': 'No user found with this email'}, status=404)

            otp = send_otp(email)
            otp_entry = PasswordResetOTP(email=email, otp=otp)
            otp_entry.save()  

            return JsonResponse({'message': 'OTP sent to your email'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            input_otp = data.get('otp')
            email = data.get('email')

            if not input_otp:
                return JsonResponse({'error': 'OTP is required'}, status=400)

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            otp_entry = PasswordResetOTP.objects(email=email).order_by('-created_at').first()  
            if not otp_entry:
                return JsonResponse({'error': 'No OTP found for this email'}, status=404)

            print(f"Stored OTP: {otp_entry.otp}, Input OTP: {input_otp}")

            if otp_entry.otp != input_otp:
                return JsonResponse({'error': 'Invalid OTP'}, status=400)

            expiration_time = 10 * 60  
            current_time = timezone.now()
            created_at = otp_entry.created_at

            if created_at.tzinfo is None:  
                created_at = timezone.make_aware(created_at)
            if (current_time - created_at).total_seconds() > expiration_time:
                return JsonResponse({'error': 'OTP has expired'}, status=400)

            otp_entry.delete()  
            return JsonResponse({'message': 'OTP verified successfully. You can now reset your password.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)



from taskapp.signals import password_reset_signal


@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            email = data.get('email')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            if not new_password or not confirm_password:
                return JsonResponse({'error': 'Both new password and confirm password are required'}, status=400)

            if new_password != confirm_password:
                return JsonResponse({'error': 'Passwords do not match'}, status=400)

            try:
                
                user = Users.objects.get(email=email)

                # Hash and update the new password
                user.password = make_password(new_password)
                user.save()

                password_reset_signal.send(sender=Users, user=user)

                return JsonResponse({'message': 'Password reset successfully.'}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({'error': 'User with this email does not exist'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


from django.core.mail import send_mail
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from datetime import datetime, timedelta  # Import correctly from the datetime module
from taskapp.mongo_models import Task, ActivityLog  # Assuming Task and ActivityLog are your models

from celery import shared_task
from datetime import datetime, timedelta
from django.core.mail import send_mail
from taskapp.mongo_models import Task, ActivityLog

@csrf_exempt
def send_reminder(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            task_titles = body.get('task_titles', [])

            reminders_sent = []
            overdue_notifications_sent = []

            reminder_threshold = timezone.now() + timezone.timedelta(days=1)
            tasks_due_soon = Task.objects.filter(
                status='pending',
                due_date__lte=reminder_threshold,
                title__in=task_titles
            )

            for task in tasks_due_soon:
                # Call the Celery task
                send_reminder_email.delay(task.title)  # Schedule the reminder email
                reminders_sent.append({
                    'task_title': task.title,
                    'description': f'Reminder scheduled for task {task.title}.'
                })

            # Send overdue notifications for pending tasks
            overdue_tasks = Task.objects.filter(
                status='pending',
                due_date__lt=timezone.now(),
                title__in=task_titles
            )

            for task in overdue_tasks:
                users = task.assigned_to
                for user in users:
                    send_notification(user, task, overdue=True)
                    overdue_notifications_sent.append({
                        'task_title': task.title,
                        'description': f'Overdue notification sent for task {task.title}.'
                    })

            return JsonResponse({
                'message': 'Notifications processed successfully.',
                'reminders_sent': reminders_sent,
                'overdue_notifications_sent': overdue_notifications_sent
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)




def send_notification(user, task, overdue=False):
    """Send notification email to the user about the task."""
    if overdue:
        subject = f'Overdue Task Notification: {task.title}'
        message = f'Task "{task.title}" is overdue! Please complete it as soon as possible. Due date was {task.due_date}.'
    else:
        subject = f'Task Reminder: {task.title}'
        message = f'Reminder: Task "{task.title}" is approaching its deadline on {task.due_date}.'

    # Sending the email notification
    send_mail(
        subject,
        message,
        'kitecareer2018@gmail.com', 
        [user.email],  
        fail_silently=False,
    )


from django.shortcuts import get_object_or_404
from .mongo_models import Task, Comment
from django.contrib.auth.decorators import login_required
from mongoengine.connection import get_db
from gridfs import GridFS
from io import BytesIO
from django.core.files.base import ContentFile
import base64

@csrf_exempt
def add_comment(request, project_id):
    if request.method == 'POST':
        try:
            # Load JSON data from the request body
            data = json.loads(request.body)

            # Check if data is a dictionary
            if not isinstance(data, dict):
                return JsonResponse({'status': 'error', 'message': 'Invalid data format. Expected a JSON object.'}, status=400)

            # Retrieve the project by its ID
            project = Project.objects.get(id=project_id)

            # Extract content and created_by from the JSON payload
            content = data.get('content')
            file = data.get('file')
            username = data.get('name')
            # name = data.get('name')

            created_by_id = data.get('created_by')

            if not content:
                return JsonResponse({'status': 'error', 'message': 'Content is required.'}, status=400)

            # Initialize flags for file status
            file_received = False
            uploaded_file = None

            # Check if the request has a file uploaded
            if 'file' in request.FILES:
                uploaded_file = request.FILES['file']
                file_received = True

                try:
                    # Create a ContentFile object from the uploaded file
                    content_file = ContentFile(uploaded_file.read(), name=uploaded_file.name)

                    # Create an ImageUpload instance and save the file
                    image_upload = ImageUpload()
                    image_upload.image.put(content_file, content_type=uploaded_file.content_type)
                    image_upload.save()  # Save the image file to the database

                except Exception as e:
                    return JsonResponse({'status': 'error', 'message': f'Error processing the file: {str(e)}'}, status=400)

            # Create a new Comment object
            comment = Comment (
                content=content,
                project=project,
                name=username,
                file=file,
                created_by=created_by_id
            )

            # Save the Comment object
            comment.save()
            
            assigned_users = project.assigned_users  # MongoEngine stores this as a list

#             # Send notifications to each assigned user
            for user in assigned_users:
                send_mail(
                    subject="New Comment Added",
                    message=f"A new comment has been added to the task: {Task}\n\nComment: {content}",
                    from_email=DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],  # Assuming user object has an email attribute
                    fail_silently=False,
                )

            # Return a success response
            return JsonResponse({
                'status': 'success',
                'message': 'Comment has been added successfully!',
                'project_id': str(project.id),
                'file_received': file_received
            })

        except Project.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found.'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON data.'}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

from django.core.files.base import ContentFile
from secproject.settings import DEFAULT_FROM_EMAIL


def get_file_from_gridfs(file_id):
    """Retrieve a file from GridFS using its ID."""
    db = get_db()  # Get the MongoDB connection
    fs = GridFS(db)  # Initialize GridFS
    return fs.get(ObjectId(file_id))  # Retrieve the file by its ID

def download_file(request, file_id):
    """Download a file from GridFS."""
    try:
        file = get_file_from_gridfs(file_id)  # Get the file
        response = FileResponse(file, as_attachment=True, filename=file.filename)  # Prepare the response
        return response  # Return the file response

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)  # Handle errors


def notify_user(user, comment):
    """Function to handle user notification logic."""
    # Implement your notification logic (e.g., sending an email or push notification)
    print(f"Notification sent to {user.username}: {comment.content}")

@csrf_exempt
def get_comments(request, project_id):
    if request.method == 'GET':
        try:
            project = Project.objects.get(id=project_id)
            comments = Comment.objects.filter(project=project)

            comments_data = []
            for comment in comments:
                user = comment.created_by
                usersname = comment.name
                username = user.name if user else 'Anonymous'
                name = f"{user.first_name} {user.last_name}".strip() if user else 'Anonymous'
                
                # file_data = None
                # if comment.file:  # Check if there's a file
                #     file_data = {'filename': comment.file.filename}

                replies = Reply.objects.filter(comment=comment)
                replies_data = [
                    {
                        'content': reply.content,
                        'id': str(reply.id),
                        'created_at': reply.created_at,
                        'name': reply.name
                    }
                    for reply in replies
                ]

                comments_data.append({
                    'content': comment.content,
                    'id': str(comment.id),
                    'file': comment.file, # Include file data if it exists
                    'name': usersname,
                    'replies': replies_data 
                })

            assigned_users = project.assigned_users
            users_data = [{'username': user.username} for user in assigned_users]

            return JsonResponse({
                'status': 'success',
                'comments': comments_data,
                'assigned_users': users_data
            })

        except DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found.'}, status=404)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

@csrf_exempt
def delete_comment(request, comment_id):
    try:
        # Ensure the comment_id is a valid ObjectId
        if not ObjectId.is_valid(comment_id):
            return JsonResponse({'status': 'error', 'message': 'Invalid comment ID format.'}, status=400)

        # Retrieve the comment by _id (which is the MongoDB identifier)
        comment = Comment.objects.get(id=ObjectId(comment_id))
        replies = Reply.objects.filter(comment=comment)
        replies.delete()

        # Delete the comment
        comment.delete()

        return JsonResponse({'status': 'success', 'message': 'Comment deleted successfully.'})

    except DoesNotExist:
        # Return an error if the comment does not exist
        return JsonResponse({'status': 'error', 'message': 'Comment not found.'}, status=404)

    except Exception as e:
        # Handle any other exceptions
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    

@csrf_exempt   
def reply_to_comment(request, comment_id):
    if request.method == 'POST':
        try:
            # Ensure the comment_id is a valid ObjectId
            if not ObjectId.is_valid(comment_id):
                return JsonResponse({'status': 'error', 'message': 'Invalid comment ID format.'}, status=400)

            # Retrieve the original comment by _id
            original_comment = Comment.objects.get(id=ObjectId(comment_id))

            # Parse the JSON body
            try:
                data = json.loads(request.body)
                content = data.get('content')
                name = data.get('name')
                print("name", name)

            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': 'Invalid JSON format.'}, status=400)

            # Validate that content is provided
            if not content:
                return JsonResponse({'status': 'error', 'message': 'Reply content is required.'}, status=400)

            # Create a new reply with the current time as created_at
            reply = Reply(content=content, comment=original_comment, created_at=str(datetime.utcnow()),name = name)
            reply.save()

            return JsonResponse({'status': 'success', 'message': 'Reply posted successfully.'})

        except DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Comment not found.'}, status=404)
        
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)


import requests

API_KEY = '404a593298ced5ba75f44baf49ce7daf'  
BASE_URL = 'https://api.openweathermap.org/data/2.5/weather'

def get_current_weather(request, city):
    try:
        # Construct the API request URL
        url = f"{BASE_URL}?q={city}&appid={API_KEY}&units=metric"
        
        # Send the request to the weather API
        response = requests.get(url)
        data = response.json()

        if response.status_code != 200:
            return JsonResponse({
                'status': 'error',
                'message': data.get('message', 'Unable to fetch weather data.')
            }, status=response.status_code)

        weather_info = {
            'status': 'success',
            'weather': {
                'city': data['name'],
                'temperature': data['main']['temp'],
                'description': data['weather'][0]['description'],
                'icon': f"http://openweathermap.org/img/wn/{data['weather'][0]['icon']}@2x.png"
            }
        }

        return JsonResponse(weather_info)

    except requests.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    

@csrf_exempt
def generate_projects_summary_report(request, project_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get('user_id', '').strip()  # Get user_id from JSON data

        
            if not ObjectId.is_valid(user_id):
                return JsonResponse({"error": "Invalid user ID format."}, status=400)

            # Retrieve the user
            user = Users.objects.get(id=ObjectId(user_id))  # Use ObjectId for querying
            project = Project.objects.get(id=ObjectId(project_id))  # Ensure the project ID is valid

            # Calculate report data
            total_tasks = Task.objects(project=project).count()
            completed_tasks = Task.objects(project=project, status='done').count()
            in_progress_tasks = Task.objects(project=project, status='in progress').count()

            report_data = {
                "project_name": project.name,
                "start_date": project.start_date.isoformat(),
                "end_date": project.end_date.isoformat(),
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "in_progress_tasks": in_progress_tasks,
                "completion_percentage": (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0,
            }

            # Save the report to the database
            report = Report(
                report_type='project_summary',
                generated_by=user,
                data=report_data
            )
            report.save()

            # Return the JSON response in the required format
            return JsonResponse({"message": "Report generated successfully", "report": report_data})

        except Users.DoesNotExist:
            return JsonResponse({"error": f"User with ID {user_id} does not exist."}, status=404)
        except Project.DoesNotExist:
            return JsonResponse({"error": f"Project with ID {project_id} does not exist."}, status=404)
        except ValidationError as ve:
            return JsonResponse({"error": str(ve)}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return HttpResponseBadRequest("Invalid request method")

@csrf_exempt
def generate_project_summary_report(request):
    if request.method == 'POST':
        try:
            today = datetime.today().date()
            past_7_days = today - timedelta(days=7)

            # Fetch aggregated project data
            total_projects = Project.objects.count()
            completed_projects = Project.objects.filter(
                id__in=[task.project.id for task in Task.objects(status='done')]
            ).count()
            overdue_projects = Project.objects(end_date__lt=past_7_days).count()

            # Fetch aggregated task data
            total_tasks = Task.objects.count()
            completed_tasks = Task.objects(status='done').count()
            in_progress_tasks = Task.objects(status='in progress').count()

            # Calculate completion percentage
            completion_percentage = (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0

            # Prepare report data
            report_data = {
                "total_projects": total_projects,
                "completed_projects": completed_projects,
                "overdue_projects": overdue_projects,
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "in_progress_tasks": in_progress_tasks,
                "completion_percentage": completion_percentage,
            }

            # Save the report to the database
            report = Report(
                report_type='project_summary',
                generated_by=None,
                data=report_data
            )
            report.save()

            # Return the report in the response
            return JsonResponse({
                "message": "All projects report generated successfully",
                "report": report_data
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return HttpResponseBadRequest("Invalid request method")


@csrf_exempt
def generate_task_report(request):
    if request.method == 'POST':
        try:
            today = datetime.today().date()

            # Retrieve task data grouped by status
            total_tasks = Task.objects.count()
            completed_tasks = Task.objects(status='done')
            in_progress_tasks = Task.objects(status='in progress')
            overdue_tasks = Task.objects(due_date__lt=today, status__ne='done')  # Overdue but not done
            pending_tasks = Task.objects(status__ne='done')

            # Calculate completion percentage
            completion_percentage = (completed_tasks.count() / total_tasks) * 100 if total_tasks > 0 else 0

            # Extract task details into lists
            completed_task_details = [
                {"task_id": str(task.id), "title": task.title, "due_date": task.due_date.isoformat()}
                for task in completed_tasks
            ]

            in_progress_task_details = [
                {"task_id": str(task.id), "title": task.title, "due_date": task.due_date.isoformat()}
                for task in in_progress_tasks
            ]

            overdue_task_details = [
                {"task_id": str(task.id), "title": task.title, "due_date": task.due_date.isoformat()}
                for task in overdue_tasks
            ]

            pending_task_details = [
                {"task_id": str(task.id), "title": task.title, "due_date": task.due_date.isoformat()}
                for task in pending_tasks
            ]

            # Prepare the final report data
            report_data = {
                "total_tasks": total_tasks,
                "completed_tasks_count": completed_tasks.count(),
                "in_progress_tasks_count": in_progress_tasks.count(),
                "overdue_tasks_count": overdue_tasks.count(),
                "pending_tasks_count": pending_tasks.count(),
                "completion_percentage": completion_percentage,
                "completed_tasks": completed_task_details,
                "in_progress_tasks": in_progress_task_details,
                "overdue_tasks": overdue_task_details,
                "pending_tasks": pending_task_details,
            }

            # Return the report in the response
            return JsonResponse({
                "message": "Detailed task report generated successfully",
                "report": report_data
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return HttpResponseBadRequest("Invalid request method")


@csrf_exempt
def generate_activity_report(request, user_id):
    if request.method == 'POST':
        # Validate if the user_id is a valid ObjectId
        if not ObjectId.is_valid(user_id):
            return JsonResponse({"error": "Invalid user ID format."}, status=400)

        try:
            # Retrieve the user by ID using ObjectId conversion
            user = Users.objects.get(id=ObjectId(user_id))

            # Generate activity report data (Example logic)
            total_tasks = Task.objects(assigned_to=user).count()
            completed_tasks = Task.objects(assigned_to=user, status='done').count()
            overdue_tasks = Task.objects(assigned_to=user, due_date__lt=datetime.now(), status__ne='done').count()

            report_data = {
                "user": user.username,
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "overdue_tasks": overdue_tasks,
                "completion_percentage": (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0,
            }

            # Save the activity report with the correct report_type
            report = Report(
                report_type='user_activity',  # Corrected report type
                generated_by=user,
                data=report_data
            )
            report.save()

            return JsonResponse({"message": "Activity report generated successfully", "report": report_data})

        except DoesNotExist:
            return JsonResponse({"error": f"User with ID {user_id} does not exist."}, status=404)

        except ValidationError as e:
            return JsonResponse({"error": f"Validation error: {str(e)}"}, status=400)

    return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
def view_reports(request):
    try:
        # Query both project summary and activity reports
        reports = Report.objects(
            Q(report_type='project_summary') | Q(report_type='user_activity')
        )

        if not reports:
            return JsonResponse({"message": "No reports found."}, status=404)

        report_list = [
            {
                "report_type": report.report_type,
                "generated_by": report.generated_by.username if report.generated_by else None,
                "created_at": report.created_at.isoformat(),
                "data": report.data,
            }
            for report in reports
        ]

        return JsonResponse(report_list, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


