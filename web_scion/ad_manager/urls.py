from django.conf.urls import patterns, url
from ad_manager import views


urlpatterns = patterns('',
    url(r'^isds/$', views.ISDListView.as_view(), name='list_isds'),
    url(r'^isds/(?P<pk>\d+)/$', views.ISDDetailView.as_view(), name='isd_detail'),
    url(r'^ads/(?P<pk>\d+)/$', views.ADDetailView.as_view(), name='ad_detail'),
    # url(r'^ads$', views.ADListView.as_view(), name='list_ads'),
)