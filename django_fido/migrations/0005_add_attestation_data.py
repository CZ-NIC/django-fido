# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-05-21 11:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_fido', '0004_remove_u2f_device'),
    ]

    operations = [
        migrations.AddField(
            model_name='authenticator',
            name='attestation_data',
            field=models.TextField(null=True),
        ),
    ]