from django.db import models


# Create your models here.
class Game(models.Model):
    name = models.CharField(max_length=255, verbose_name='Game name')

    def __str__(self):
        return self.name


class Title(models.Model):
    title_id = models.CharField(max_length=20, verbose_name='Title ID')
    game = models.ForeignKey('Game')

    def __str__(self):
        return '{0} [{1}]'.format(self.game.name, self.title_id)


class Build(models.Model):

    build_hash = models.CharField(max_length=40, verbose_name='Build commit hash')

    def _get_commit_id(self):
        return self.build_hash[:8]

    build_id = property(_get_commit_id)

    def __str__(self):
        return 'Cxbx-Reloaded [{0}]'.format(self.build_id)


class Executable(models.Model):

    file_name = models.CharField(max_length=256)
    signature = models.CharField(max_length=512, unique=True)
    disk_path = models.CharField(max_length=1024)

    title = models.ForeignKey(Title)

    def __str__(self):
        return self.file_name
