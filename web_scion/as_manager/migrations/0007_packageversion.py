# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0006_auto_20150311_1022'),
    ]

    operations = [
        migrations.CreateModel(
            name='PackageVersion',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, verbose_name='ID', auto_created=True)),
                ('name', models.CharField(max_length=50)),
                ('date_created', models.DateTimeField()),
                ('size', models.IntegerField()),
                ('filepath', models.CharField(max_length=400)),
            ],
            options={
                'verbose_name': 'Package version',
            },
            bases=(models.Model,),
        ),
    ]
