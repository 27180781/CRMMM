#!/bin/sh

# המתן למסד הנתונים להיות מוכן
echo "Waiting for database..."
python -c "
import os, time, psycopg2
db_url = os.environ.get('DATABASE_URL')
retries = 15
while retries > 0:
    try:
        psycopg2.connect(db_url)
        print('DB Ready!')
        break
    except psycopg2.OperationalError:
        retries -= 1
        print('Waiting for DB...')
        time.sleep(3)
"

# החל את עדכוני מסד הנתונים
echo "Running database migrations..."
flask db upgrade

# הפעל את שרת האפליקציה
echo "Starting Gunicorn server..."
exec gunicorn --bind 0.0.0.0:80 --forwarded-allow-ips="*" app:app