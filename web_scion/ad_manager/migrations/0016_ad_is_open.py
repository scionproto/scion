# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0015_auto_20150527_1503'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='is_open',
            field=models.BooleanField(default=True),
            preserve_default=True,
        ),
    ]
