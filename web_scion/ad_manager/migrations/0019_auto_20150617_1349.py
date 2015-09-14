# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0018_auto_20150615_0937'),
    ]

    operations = [
        migrations.RenameField(
            model_name='connectionrequest',
            old_name='router_ip',
            new_name='router_bound_ip',
        ),
        migrations.RenameField(
            model_name='connectionrequest',
            old_name='router_port',
            new_name='router_bound_port',
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='router_public_ip',
            field=models.GenericIPAddressField(null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='router_public_port',
            field=models.IntegerField(null=True, blank=True),
            preserve_default=True,
        ),
    ]
