# Generated by Django 3.1a1 on 2020-06-25 21:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('armory_main', '0014_auto_20200624_2144'),
    ]

    operations = [
        migrations.AddField(
            model_name='ipaddress',
            name='completed',
            field=models.BooleanField(default=False),
        ),
    ]
