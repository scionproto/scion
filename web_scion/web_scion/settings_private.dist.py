import os

WEB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'j(ssxvxi!8t)-p80t3&(va2oa510%4q)j$njf(zius3fasdfasdfas'

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES1 = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(WEB_DIR, 'db.sqlite3'),
    }
}

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

### Two factor authlentication
TWO_FACTOR_SMS_GATEWAY = 'two_factor.gateways.fake.Fake'
# TWO_FACTOR_SMS_GATEWAY = 'two_factor.gateways.twilio.gateway.Twilio'

TWILIO_ACCOUNT_SID = ''
TWILIO_AUTH_TOKEN = ''
TWILIO_CALLER_ID = ''
