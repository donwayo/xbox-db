from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^upload$', views.upload, name='upload'),
    url(r'^games/$', views.GamesView.as_view(), name='games')
]
