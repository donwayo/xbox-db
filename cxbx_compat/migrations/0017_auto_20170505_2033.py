# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-05-05 20:33
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cxbx_compat', '0016_auto_20170421_1438'),
    ]

    operations = [
        migrations.AddField(
            model_name='game',
            name='image',
            field=models.CharField(default='', max_length=255, verbose_name='Image'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='executable',
            name='cert_name',
            field=models.CharField(max_length=255, verbose_name='Internal name'),
        ),
    ]
