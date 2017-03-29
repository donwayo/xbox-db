from django.contrib import admin

# Register your models here.
from .models import Build, Game, Title, Executable

admin.site.register(Build)
admin.site.register(Game)
admin.site.register(Title)
admin.site.register(Executable)
