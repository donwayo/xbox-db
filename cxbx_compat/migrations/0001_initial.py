# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-03-27 15:46
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Build',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('build_id', models.IntegerField(verbose_name='Build commit ID')),
                ('date', models.DateTimeField(verbose_name='Build date')),
            ],
        ),
        migrations.CreateModel(
            name='Game',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(verbose_name='Game name')),
            ],
        ),
        migrations.CreateModel(
            name='Title',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title_id', models.IntegerField(verbose_name='Title ID')),
                ('game', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cxbx_compat.Game')),
            ],
        ),
    ]