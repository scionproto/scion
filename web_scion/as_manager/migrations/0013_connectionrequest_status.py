# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0012_connectionrequest'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectionrequest',
            name='status',
            field=models.CharField(max_length=20, default='NONE', choices=[('NONE', 'NONE'), ('SENT', 'SENT'), ('APPROVED', 'APPROVED'), ('DECLINED', 'DECLINED')]),
            preserve_default=True,
        ),
    ]
