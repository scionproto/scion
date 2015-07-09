# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0007_packageversion'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ad',
            name='id',
            field=models.IntegerField(primary_key=True, serialize=False),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='isd',
            name='id',
            field=models.IntegerField(primary_key=True, serialize=False),
            preserve_default=True,
        ),
    ]
