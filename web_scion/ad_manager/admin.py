# External packages
from django.contrib import admin

# SCION
from ad_manager.models import (
    AD,
    BeaconServerWeb,
    CertificateServerWeb,
    ConnectionRequest,
    DnsServerWeb,
    ISD,
    PathServerWeb,
    RouterWeb,
)


class SortRelatedAdmin(admin.ModelAdmin):
    list_select_related = True

    def get_queryset(self, request):
        # Add ordering
        return super().get_queryset(request).order_by('id')


class ADAdmin(SortRelatedAdmin):
    pass
admin.site.register(AD, ADAdmin)


class ISDAdmin(SortRelatedAdmin):
    pass
admin.site.register(ISD, ISDAdmin)


class ServerAdmin(admin.ModelAdmin):
    list_select_related = True

    def get_queryset(self, request):
        # Add ordering
        return super().get_queryset(request).order_by('ad_id')


class BeaconServerAdmin(ServerAdmin):
    pass
admin.site.register(BeaconServerWeb, BeaconServerAdmin)


class CertificateServerAdmin(ServerAdmin):
    pass
admin.site.register(CertificateServerWeb, CertificateServerAdmin)


class PathServerAdmin(ServerAdmin):
    pass
admin.site.register(PathServerWeb, PathServerAdmin)


class RouterAdmin(ServerAdmin):
    pass
admin.site.register(RouterWeb, RouterAdmin)


class DnsServerAdmin(ServerAdmin):
    pass
admin.site.register(DnsServerWeb, DnsServerAdmin)


admin.site.register(ConnectionRequest)
