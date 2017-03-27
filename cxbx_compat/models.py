from django.db import models


# Create your models here.
class Game(models.Model):
    name = models.TextField(verbose_name='Game name')


class Title(models.Model):
    title_id = models.IntegerField(verbose_name='Title ID')
    game = models.ForeignKey('Game')


class Build(models.Model):
    build_id = models.IntegerField(verbose_name='Build commit ID')
    date = models.DateTimeField(verbose_name='Build date')
