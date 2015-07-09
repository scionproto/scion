# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0014_auto_20150519_1535'),
    ]

    operations = [
        migrations.CreateModel(
            name='DnsServerWeb',
            fields=[
                ('id', models.AutoField(primary_key=True, verbose_name='ID', serialize=False, auto_created=True)),
                ('addr', models.GenericIPAddressField()),
                ('name', models.CharField(null=True, max_length=20)),
            ],
            options={
                'verbose_name': 'DNS server',
            },
        ),
        migrations.AddField(
            model_name='ad',
            name='dns_domain',
            field=models.CharField(null=True, blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='dnsserverweb',
            name='ad',
            field=models.ForeignKey(to='ad_manager.AD'),
        ),
        migrations.AlterUniqueTogether(
            name='dnsserverweb',
            unique_together=set([('ad', 'addr')]),
        ),
    ]
