# secproject/celery.py
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secproject.settings')

app = Celery('secproject')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
