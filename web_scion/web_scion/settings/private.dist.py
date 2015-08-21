from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TEMPLATE_DEBUG = True
ALLOWED_HOSTS = []

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'CHANGE_THIS!xxxxxxxxxxxxxxxxxx'

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(WEB_SCION_DIR, 'db.sqlite3'),
    }
}

"""
# PostgreSQL settings
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'sciondb',
        'USER': 'scionuser',
        'PASSWORD': 'scionpass',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
"""

INSTALLED_APPS += (
    # 'debug_toolbar',
)

# Two factor authlentication
TWO_FACTOR_SMS_GATEWAY = 'two_factor.gateways.fake.Fake'
# TWO_FACTOR_SMS_GATEWAY = 'two_factor.gateways.twilio.gateway.Twilio'

TWILIO_ACCOUNT_SID = ''
TWILIO_AUTH_TOKEN = ''
TWILIO_CALLER_ID = ''
