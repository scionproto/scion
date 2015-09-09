# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields
import ad_manager.util.common


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0021_auto_20150729_1154'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='original_topology',
            field=jsonfield.fields.JSONField(default=ad_manager.util.common.empty_dict),
            preserve_default=True,
        ),
    ]
