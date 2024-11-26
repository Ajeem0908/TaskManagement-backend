from django.core.mail import send_mail
from django.conf import settings
from mongoengine import signals
from taskapp.mongo_models import Users, Comment
from django.db.models.signals import post_save
from django.dispatch import receiver

def send_welcome_email(sender, document, **kwargs):
    """Function to send a welcome email after user registration"""
    if kwargs.get('created', False):  
        subject = 'Welcome to kitecareer!'
        message = f"Hi {document.username},\n\nWelcome aboard TaskApp! 🎉 We're excited to have you join our community. TaskApp is your one-stop solution to staying on top of your tasks and boosting productivity. Whether it's managing deadlines or organizing your day, we've got your back! 🚀\n\nDive in, explore, and feel free to reach out if you need anything. Together, let's achieve greatness!\n\nCheers,\nThe TaskApp Team"
        from_email = settings.DEFAULT_FROM_EMAIL

        recipient_list = [document.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            print(f"Welcome email sent to {document.email}")
        except Exception as e:
            print(f"Error sending email: {str(e)}")


from django.core.mail import send_mail
from django.conf import settings
from django.dispatch import Signal, receiver
from django.utils.html import format_html

password_reset_signal = Signal()


@receiver(password_reset_signal)
def send_password_reset_email(sender, **kwargs):
    user = kwargs.get('user')
    
    if user:
        subject = 'Password Reset Successfully!'

        message = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        padding: 20px;
                    }}
                    .container {{
                        background-color: #ffffff;
                        border-radius: 8px;
                        padding: 20px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }}
                    h1 {{
                        color: #333333;
                    }}
                    p {{
                        font-size: 16px;
                        line-height: 1.5;
                        color: #555555;
                    }}
                    .footer {{
                        margin-top: 20px;
                        font-size: 12px;
                        color: #888888;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Password Reset Successfully!</h1>
                    <p>Hi {user.username},</p>
                    <p>Your password has been reset successfully. If you did not request this change, please contact us immediately.</p>
                    <p>Best regards,<br>The TaskApp Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply.</p>
                </div>
            </body>
            </html>
        """
        
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False, html_message=message)
            print(f"Password reset email sent to {user.email}")
        except Exception as e:
            print(f"Error sending password reset email: {str(e)}")




# signals.py

from django.dispatch import receiver
from django.core.mail import send_mail

send_notification_signal = Signal()

@receiver(send_notification_signal)
def send_notification(sender, user, task, overdue=False, **kwargs):
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
        'kitecareer2018@gmail.com',  # Replace with your from email
        [user.email],  # Email address of the user
        fail_silently=False,
    )



@receiver(post_save, sender=Comment)
def notify_assigned_users_on_comment(sender, instance, created, **kwargs):
    if created:
        task = instance.task
        comment_content = instance.content
        
        # Get the users assigned to the task's project
        assigned_users = task.get_assigned_users()

        # Send an email notification to each assigned user
        for user in assigned_users:
            send_mail(
                'New Comment on Task',
                f'A new comment has been added to the task "{task.title}":\n\n{comment_content}',
                'kitecareer2018@gmail.com',  # Replace with your actual sender email
                [user.email],
                fail_silently=False,
            )