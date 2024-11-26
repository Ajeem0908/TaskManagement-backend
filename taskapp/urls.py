from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import path
from taskapp import views
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    project_list_api, project_detail_api, create_project, update_project, delete_project,
    register_user,  users_view, edit_user,login_user, get_user_by_id, delete_user,
    task_list_api, task_detail_api, create_task, update_task, delete_task,TaskDetailByNameAPIView,SearchByCategoryAPIView,
     tag_detail_api, create_tag, update_tag, tag_list_api, delete_tag, create_activity_log, get_activity_logs,
    delete_activity_log,update_activity_log, get_all_detail, send_message, get_message, get_conversation,search_users,DashboardCountsView,search_users_chat,delete_message,create_notification_log,send_message_notification,get_all_messages,get_all_users,send_reminder, add_comment, get_comments,get_current_weather, generate_project_summary_report,generate_activity_report, view_reports,generate_projects_summary_report,generate_task_report,delete_comment,reply_to_comment

)

schema_view = get_schema_view(
    openapi.Info(
        title="Your API Documentation",            
        default_version='v1',                      
        description="API documentation for your project", 
        terms_of_service="https://www.google.com/policies/terms/",  
        contact=openapi.Contact(email="contact@yourapi.local"),    
        license=openapi.License(name="BSD License"),  
    ),
    public=True,  
    permission_classes=(permissions.AllowAny,), 
)
urlpatterns = [
    # path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    
    path('search/<str:category>/<str:query>/', SearchByCategoryAPIView.as_view(), name='search_by_category'),
    path('register/', register_user, name='register_user'), 
    path('login/', login_user, name='login_user'),
    # path('manager/login/', login_manager ,name='login_manager'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
    # path('api/token/', token_view, name='token'),
    # path('user/', UserListView.as_view(), name='user-list'),

    path('users/',  get_all_users, name='users_view'),
    path('users/search/', search_users_chat, name='search_users'),
    path('users/get/<str:user_pk>/',get_user_by_id,name='get_user_by_id'),
    path('users/edit/<str:user_pk>/', edit_user, name='edit_user'),
    path('users/delete/<str:user_pk>/', delete_user, name='delete_user'),

    path('projects/create/', create_project, name='create_project'),
    path('projects/', project_list_api, name='project_list_api'),  
    path('projects/<str:project_id>/', project_detail_api, name='project_detail_api'),
    path('projects/update/<str:project_id>/', update_project, name='update_project'), 
    path('projects/delete/<str:project_id>/', delete_project, name='delete_project'),  
    
    path('tasks/create/', create_task, name='create_task'),
    path('tasks/', task_list_api, name='task_list_api'), 
    path('tasks/<str:task_name>/', task_detail_api, name='task_detail_api'),     
    path('tasks/update/<str:task_id>/', update_task, name='update_task'),  
    path('tasks/delete/<str:task_id>/', delete_task, name='delete_task'), 
    
    path('tags/create/', create_tag, name='create_tag'),  
    path('tags/', tag_list_api, name='tag_list_api'),
    path('tags/delete/<str:tag_name>/', delete_tag, name='delete_tag'),   
    path('tags/<str:tag_id>/', tag_detail_api, name='tag_detail_api'),  
    path('tags/update/<str:tag_name>/', update_tag, name='update_tag'),  
     
    path('activity/create/', create_activity_log, name='create_activity_log'),
    path('get_activity_logs/', get_activity_logs, name='get_activity_logs'),
    path('activity/delete/<str:log_id>/',delete_activity_log, name='delete_activity_log'),
    path('activity/update/<str:log_id>/',update_activity_log, name='update_activity_log'),

    path('send_message/', send_message, name='send_message'),
    path('messages/api/', get_all_messages, name='get_all_messages'),
    path('messages/', get_message, name='get_message'),
    path('messages/conversation/', get_conversation, name='get_conversation'),
    path('delete_message/', delete_message, name='delete_message'),


    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    
    

    # http://192.168.1.16:8000/delete_message/?message_id=66f63dda0b4834861b91894b&delete_all=true


    path('api/search_users/<str:query>/', search_users, name='search_users'),
    path('user/<str:user_id>/details/', get_all_detail, name='user-details'),
    path('counts/', DashboardCountsView.as_view(), name='dashboard_counts'),

    path('notifications/', create_notification_log, name='create_notification'),
    path('send_message_notification/', send_message_notification, name='send_message_notification'),


    path('send-reminders/', send_reminder, name='send_reminders'),

    path('project/<str:project_id>/comment/', add_comment, name='add_comment'),
    path('task/<str:project_id>/comments/', get_comments, name='get_comments'),
    path('delete/<str:comment_id>/', delete_comment, name='delete_comment'),
    path('reply/<str:comment_id>/', reply_to_comment, name='reply_to_comment'),

    
    path('weather/<str:city>/', get_current_weather, name='get_current_weather'),

    path('report/generate/<str:project_id>/', generate_projects_summary_report, name='generate_project_summary'),
    path('reports/generate/all/', generate_project_summary_report, name='generate_project_summary_report'),
    path('generate_task_report/',generate_task_report,name='generate_task_summary_report'),
    path('reports/activity/<str:user_id>/', generate_activity_report, name='activity_report'),
    path('reports/view_all/', view_reports,name='view_reports' ),

]

