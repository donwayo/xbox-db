from django.contrib import admin

# Register your models here.
from .models import Build, Game, Title, Executable, XDKLibrary

admin.site.register(Build)
admin.site.register(Game)
admin.site.register(Title)
admin.site.register(Executable)
admin.site.register(XDKLibrary)

