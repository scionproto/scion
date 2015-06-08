# External packages
from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib.auth.views import login
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect

# SCION
from ad_manager.admin import admin_site

urlpatterns = patterns(
    '',
    url(r'^$', lambda _: HttpResponseRedirect(reverse('list_isds'))),
    url(r'^admin/', include(admin_site.urls)),
    url(r'^ad_manager/', include('ad_manager.urls')),
)


if settings.ENABLED_2FA:
    # 2FA with Twilio
    from two_factor.urls import urlpatterns as tf_urls
    from two_factor.gateways.twilio.urls import urlpatterns as tf_twilio_urls

    urlpatterns += patterns(
        '',
        url(r'', include(tf_urls + tf_twilio_urls, 'two_factor')),
    )
    settings.LOGIN_URL = reverse_lazy('two_factor:login')

else:
    urlpatterns += patterns(
        '',
        url(r'^login/$', login, {'template_name': 'admin/login.html'}),
    )
    settings.LOGIN_URL = '/login/'
