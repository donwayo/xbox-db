release: echo "from django.contrib.auth.models import User; User.objects.create_superuser('wayo', 'guayin@gmail.com', '$PASSWORD')" | python manage.py shell
web: gunicorn xdb.wsgi
