# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0008_auto_20150420_0959'),
    ]

    operations = [
        migrations.AddField(
            model_name='routerweb',
            name='interface_addr',
            field=models.IPAddressField(default='0.0.0.0'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='interface_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='interface_toaddr',
            field=models.IPAddressField(default='0.0.0.0'),
            preserve_default=False,
        ),
    ]
