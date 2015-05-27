# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0002_auto_20150304_1313'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='routerweb',
            unique_together=set([('ad', 'addr')]),
        ),
    ]
