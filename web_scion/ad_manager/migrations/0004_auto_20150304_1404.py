# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0003_auto_20150304_1402'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='beaconserverweb',
            unique_together=set([('ad', 'addr')]),
        ),
        migrations.AlterUniqueTogether(
            name='certificateserverweb',
            unique_together=set([('ad', 'addr')]),
        ),
        migrations.AlterUniqueTogether(
            name='pathserverweb',
            unique_together=set([('ad', 'addr')]),
        ),
    ]
