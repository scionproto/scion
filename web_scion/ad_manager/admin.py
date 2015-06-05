# External packages
from django.contrib import admin
from django.contrib.auth import get_permission_codename
from django.core.urlresolvers import reverse
from guardian.admin import GuardedModelAdmin

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


class PrivilegedChangeAdmin(GuardedModelAdmin):
    list_select_related = True

    def has_change_permission(self, request, obj=None):
        opts = self.opts
        codename = get_permission_codename('change', opts)

        # If there is an 'ad' attribute then it's a foreign key, so extend
        # user permissions for this ad to the current object
        ad = getattr(obj, 'ad', None)
        if ad and isinstance(ad, AD):
            obj = ad
            codename = 'change_ad'
        return request.user.has_perm("%s.%s" % (opts.app_label, codename), obj)

    def get_readonly_fields(self, request, obj=None):
        """
        Make fields specified in 'privileged fields' read-only
        """
        fields = super().get_readonly_fields(request, obj)
        if not request.user.has_perm('change_ad'):
            fields += self.privileged_fields
        return fields

    def get_queryset(self, request):
        # Add ordering
        return super().get_queryset(request).order_by('ad_id')


@admin.register(AD, ISD)
class SortRelatedAdmin(PrivilegedChangeAdmin):
    privileged_fields = ('isd', 'is_core_ad',)


@admin.register(BeaconServerWeb,
                CertificateServerWeb,
                PathServerWeb,
                DnsServerWeb,
                RouterWeb)
class ServerAdmin(PrivilegedChangeAdmin):
    privileged_fields = ('ad',)
    readonly_fields = ('ad_link',)
    fields = ('name', 'addr', ('ad', 'ad_link'),)

    def ad_link(self, obj):
        link = reverse('admin:{}_ad_change'.format(self.opts.app_label),
                       args=[obj.ad.id])
        return '<a href="{}">Change AD</a>'.format(link)
    ad_link.allow_tags = True
    # FIXME hack. How to remove this completely?
    ad_link.short_description = ':'


# Misc admin models
admin.site.register(ConnectionRequest)
