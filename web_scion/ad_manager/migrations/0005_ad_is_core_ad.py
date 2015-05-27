# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0004_auto_20150304_1404'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='is_core_ad',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
