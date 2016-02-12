# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='BeaconServerWeb',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('addr', models.IPAddressField()),
                ('as', models.ForeignKey(to='ad_manager.AS')),
            ],
            options={
                'verbose_name': 'Beacon server',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='CertificateServerWeb',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('addr', models.IPAddressField()),
                ('as', models.ForeignKey(to='ad_manager.AS')),
            ],
            options={
                'verbose_name': 'Certificate server',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='PathServerWeb',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('addr', models.IPAddressField()),
                ('as', models.ForeignKey(to='ad_manager.AS')),
            ],
            options={
                'verbose_name': 'Path server',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RouterWeb',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('addr', models.IPAddressField()),
                ('as', models.ForeignKey(to='ad_manager.AS')),
            ],
            options={
                'verbose_name': 'Router',
            },
            bases=(models.Model,),
        ),
        migrations.AlterModelOptions(
            name='as',
            options={'verbose_name': 'AS'},
        ),
        migrations.AlterModelOptions(
            name='isd',
            options={'verbose_name': 'ISD'},
        ),
        migrations.RemoveField(
            model_name='isd',
            name='name',
        ),
    ]
