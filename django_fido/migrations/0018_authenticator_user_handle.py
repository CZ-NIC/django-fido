# Generated by Django 2.2.24 on 2021-11-04 22:57

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_fido", "0017_metadata_update"),
    ]

    operations = [
        migrations.AddField(
            model_name="authenticator",
            name="user_handle",
            field=models.TextField(blank=True, unique=True, null=True),
        ),
    ]
