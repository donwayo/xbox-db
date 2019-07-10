from django.db import models


# Create your models here.
class Game(models.Model):
    name = models.CharField(max_length=255, verbose_name='Game name')
    image = models.CharField(max_length=255, verbose_name='Image')

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Title(models.Model):
    title_id = models.CharField(max_length=20, verbose_name='Title ID', unique=True)
    game = models.ForeignKey('Game', on_delete=models.CASCADE)

    def save(self, force_insert=False, force_update=False, **kwargs):
        self.title_id = self.title_id.upper()
        super(Title, self).save(force_insert, force_update, **kwargs)

    def __str__(self):
        return '{} [{}]'.format(self.game.name, self.title_id)


class Build(models.Model):

    build_hash = models.CharField(max_length=40, verbose_name='Build commit hash')

    def _get_commit_id(self):
        return self.build_hash[:8]

    build_id = property(_get_commit_id)

    def __str__(self):
        return 'Cxbx-Reloaded [{0}]'.format(self.build_id)


class XDKLibrary(models.Model):
    name = models.CharField(verbose_name='XDK Library', max_length=255)
    xdk_version = models.IntegerField(verbose_name='Library XDK version')
    qfe_version = models.IntegerField(verbose_name='QFE version')

    class Meta:
        verbose_name_plural = 'XDK Libraries'

    def __str__(self):
        return '[{1}.{2}] {0}'.format(self.name, self.xdk_version, self.qfe_version)


class Executable(models.Model):
    ACCEPTED = 1
    UNKNOWN = 0
    REJECTED = 2

    SIGNATURE_STATUS = (
        (UNKNOWN, 'Unknown'),
        (ACCEPTED, 'Accepted'),
        (REJECTED, 'Rejected')
    )

    file_name = models.CharField(max_length=255)
    cert_name = models.CharField(verbose_name='Internal name', max_length=255)
    signature = models.CharField(max_length=512)
    signature_hash = models.CharField(max_length=40, unique=True)
    disk_path = models.CharField(max_length=1024)

    title = models.ForeignKey(Title, on_delete=models.CASCADE)

    xbe_info = models.TextField(blank=True, null=True)

    xdk_libraries = models.ManyToManyField(XDKLibrary)

    signature_status = models.IntegerField(choices=SIGNATURE_STATUS, default=UNKNOWN)

    def __str__(self):
        return '{0}{1} [{2}]'.format(self.disk_path, self.file_name, self.signature_hash[:8])
