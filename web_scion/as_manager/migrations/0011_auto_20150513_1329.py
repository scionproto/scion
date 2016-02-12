# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0010_auto_20150508_1224'),
    ]

    operations = [
        migrations.AddField(
            model_name='beaconserverweb',
            name='name',
            field=models.CharField(null=True, max_length=20),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='name',
            field=models.CharField(null=True, max_length=20),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='name',
            field=models.CharField(null=True, max_length=20),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='name',
            field=models.CharField(null=True, max_length=20),
            preserve_default=True,
        ),
    ]
