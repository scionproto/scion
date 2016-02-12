# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0016_ad_is_open'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectionrequest',
            name='package_path',
            field=models.CharField(blank=True, max_length=1000, null=True),
            preserve_default=True,
        ),
    ]
