from __future__ import absolute_import
import os
from celery import Celery
from pathlib import Path
import mongoengine
from mongoengine import connect


BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
SECRET_KEY = 'django-insecure-87q@8y)mz_k43bn0h*09jgb&7n^%6$pt2=0-say#z3by8v0efl'
DEBUG = True
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '192.168.1.11', '192.168.1.15', '192.168.1.21', '192.168.1.208', '192.168.18.173']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles', 
    'django_mongoengine',     
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'taskapp',
    'corsheaders',
    'rest_framework',
    'drf_yasg',
    'channels',
    'django_celery_beat',
]

SITE_ID = 1

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
)

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
    }
}
SOCIALACCOUNT_PROVIDERS = {
    'facebook': {
        'METHOD': 'oauth2',
        'SCOPE': ['email'],  
        'FIELDS': [ 'email', 'name','phone_number'],  
        'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
        'EXCHANGE_TOKEN': True,
        'VERIFIED_EMAIL': False,
        'VERSION': 'v7.0',
    }
}


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

# SESSION_ENGINE = 'mongoengine.django.sessions'
# SESSION_COOKIE_AGE = 60

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

CORS_ALLOWED_ORIGINS = [ 
    'http://localhost:3000',
    'http://192.168.1.11:8000'
]



ROOT_URLCONF = 'secproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

ASGI_APPLICATION = 'secproject.asgi.application'

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer", 
        "hosts": [('192.168.1.11', 6379)],
        
    },
}

# MongoDB settings
MONGODB_DATABASES = {
    'default': {    
        'db': 'ideas',
        'host': 'localhost',   
        'port': 27017,
        'USERNAME': '',
        'PASSWORD': '',
        
    }
}


import mongoengine
mongoengine.connect(**MONGODB_DATABASES['default'])

# Dummy DATABASES setting
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy',
    }
}

# settings.py


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'kitecareer2018@gmail.com'  
EMAIL_HOST_PASSWORD = 'ijdp opcl cxyz ppfv'     
DEFAULT_FROM_EMAIL = 'TasK Management <kitecareer2018@gmail.com>'



# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secproject.settings')

app = Celery('secproject')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


# Broker URL for Celery (using Redis as an example)
CELERY_BROKER_URL = 'redis://localhost:6379/0'

# Optional: Celery results backend (can also be Redis)
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# Celery beat schedule for periodic tasks
CELERY_BEAT_SCHEDULE = {
    'send_reminders_task': {
        'task': 'taskapp.tasks.send_reminders',
        'schedule': 86400.0,  # Runs every 24 hours (86400 seconds)
    },
}



LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

