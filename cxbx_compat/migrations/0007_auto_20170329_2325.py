# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-03-29 21:25
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cxbx_compat', '0006_executable'),
    ]

    operations = [
        migrations.CreateModel(
            name='XDKLibrary',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('xdk_version', models.IntegerField()),
                ('qfe_version', models.IntegerField()),
            ],
        ),
        migrations.AlterField(
            model_name='executable',
            name='file_name',
            field=models.CharField(max_length=255),
        ),
        migrations.AddField(
            model_name='executable',
            name='xdk_libraries',
            field=models.ManyToManyField(to='cxbx_compat.XDKLibrary'),
        ),
    ]
