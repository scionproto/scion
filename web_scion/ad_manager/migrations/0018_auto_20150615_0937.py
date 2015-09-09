# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0017_connectionrequest_package_path'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectionrequest',
            name='router_port',
            field=models.IntegerField(default=50000),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='interface_port',
            field=models.IntegerField(default=50000),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='interface_toport',
            field=models.IntegerField(default=50000),
            preserve_default=True,
        ),
    ]
