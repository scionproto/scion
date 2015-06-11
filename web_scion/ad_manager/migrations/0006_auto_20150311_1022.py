# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0005_ad_is_core_ad'),
    ]

    operations = [
        migrations.AddField(
            model_name='routerweb',
            name='neighbor_ad',
            field=models.ForeignKey(related_name='neighbors', default='DEFAULT', to='ad_manager.AD'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='routerweb',
            name='neighbor_type',
            field=models.CharField(choices=[('CHILD', 'CHILD'), ('PARENT', 'PARENT'), ('PEER', 'PEER'), ('ROUTING', 'ROUTING')], max_length=10, default='DEFAULT'),
            preserve_default=False,
        ),
    ]
