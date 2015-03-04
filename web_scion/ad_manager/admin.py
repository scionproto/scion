from django.contrib import admin
from ad_manager.models import ISD, AD, BeaconServerWeb, PathServerWeb, \
    CertificateServerWeb, RouterWeb


for model in [ISD, AD, BeaconServerWeb, PathServerWeb, CertificateServerWeb,
              RouterWeb]:
    admin.site.register(model)