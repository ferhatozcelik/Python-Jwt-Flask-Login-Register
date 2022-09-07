import os

API_KEY = 'Basic API_KEY_TEST'
APP_SECRET_KEY = 'FERHAT_OZCELIK'
SUCCESS_MESSAGE = 'SUCCESS'

FAILED_MESSAGE = 'FAILED'
ACCESS_KEY = 'TEST'

DEBUG = False

if DEBUG:
    DATABASE_URL = 'postgresql://username:password@localhost:5432/database'
else:
    DATABASE_URL = os.environ.get('DATABASE_URL')
