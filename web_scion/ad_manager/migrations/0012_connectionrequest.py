# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ad_manager', '0011_auto_20150513_1329'),
    ]

    operations = [
        migrations.CreateModel(
            name='ConnectionRequest',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('info', models.TextField()),
                ('router_ip', models.IPAddressField()),
                ('connect_to', models.ForeignKey(to='ad_manager.AD', related_name='received_requests')),
                ('created_by', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('new_ad', models.ForeignKey(blank=True, null=True, to='ad_manager.AD')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
