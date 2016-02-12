# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0020_ad_md_host'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='as',
            options={'ordering': ['id'], 'verbose_name': 'AS'},
        ),
        migrations.AlterModelOptions(
            name='isd',
            options={'ordering': ['id'], 'verbose_name': 'ISD'},
        ),
    ]
