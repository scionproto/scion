# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0013_connectionrequest_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='beaconserverweb',
            name='addr',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='certificateserverweb',
            name='addr',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='router_ip',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='pathserverweb',
            name='addr',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='addr',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_addr',
            field=models.GenericIPAddressField(),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_toaddr',
            field=models.GenericIPAddressField(),
        ),
    ]
