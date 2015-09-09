# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0019_auto_20150617_1349'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='md_host',
            field=models.IPAddressField(default='127.0.0.1'),
            preserve_default=True,
        ),
    ]
