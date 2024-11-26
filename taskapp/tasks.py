from celery import shared_task
from django.utils import timezone
from .mongo_models import Task  # Make sure to import your Task model
from .utils import send_notification  # Import your notification function

@shared_task
def send_reminder_email(task_title):
    # Logic to send the reminder email
    task = Task.objects.filter(title=task_title).first()  # Fetch the task

    if task:
        users = task.assigned_to  # Assuming this is a ReferenceField to Users
        for user in users:
            send_notification(user, task)  # Function to send notification (email, etc.)

@shared_task
def send_reminders():
    # Logic to fetch tasks due tomorrow and send reminders
    tomorrow = timezone.now() + timezone.timedelta(days=1)
    tasks_due_soon = Task.objects.filter(due_date__date=tomorrow, status='pending')

    for task in tasks_due_soon:
        send_reminder_email.delay(task.title)  # Schedule sending the reminder email

# secproject/taskapp/tasks.py
from celery import shared_task
from .utils import create_notification  # Use the correct function name

@shared_task
def notify_user(user_id, message):
    # Call the function to send a notification
    create_notification(user_id, message)

