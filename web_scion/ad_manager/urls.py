# External packages
from django.conf.urls import patterns, url

# SCION
from ad_manager import views

isd_patterns = patterns(
    '',
    url(r'^isds/$',
        views.ISDListView.as_view(), name='list_isds'),
    url(r'^isds/(?P<pk>\d+)/$',
        views.ISDDetailView.as_view(), name='isd_detail'),
)

ad_patterns = patterns(
    '',
    url(r'^ads/(?P<pk>\d+)/$',
        views.ADDetailView.as_view(), name='ad_detail'),
    url(r'^ads/(?P<pk>\d+)/#!topology$',
        views.ADDetailView.as_view(), name='ad_detail_topology'),
    url(r'^ads/(?P<pk>\d+)/#!updates$',
        views.ADDetailView.as_view(), name='ad_detail_updates'),
    url(r'^ads/(?P<pk>\d+)/#!requests$',
        views.ADDetailView.as_view(), name='ad_connection_requests'),
    url(r'^ads/(?P<pk>\d+)/get_status$',
        views.get_ad_status, name='ad_status'),
    url(r'^ads/(?P<pk>\d+)/compare_remote_topology$',
        views.compare_remote_topology, name='compare_topology'),
    url(r'^ads/(?P<pk>\d+)/update_topology$',
        views.update_topology, name='update_topology'),
    url(r'^ads/(?P<pk>\d+)/update_action$',
        views.software_update_action, name='update_action'),
    url(r'^ads/(?P<pk>\d+)/refresh_versions$',
        views.refresh_versions, name='refresh_versions'),
    url(r'^ads/(?P<pk>\d+)/control/(?P<proc_id>[\w-]+)/$',
        views.control_process, name='control_process'),
    url(r'^ads/(?P<pk>\d+)/log/(?P<proc_id>[\w-]+)/$',
        views.read_log, name='read_log'),
    url(r'^ads/(?P<pk>\d+)/new_link/$',
        views.NewLinkView.as_view(), name='new_link'),
    url(r'^ads/(?P<pk>\d+)/group_master/$',
        views.get_group_master, name='get_group_master'),
)

connection_request_patterns = patterns(
    '',
    url(r'^connection_requests/new/(?P<pk>\d+)/$',
        views.ConnectionRequestView.as_view(), name='new_connection_request'),
    url(r'^connection_requests/sent$',
        views.list_sent_requests, name='sent_requests'),
    url(r'^connection_requests/(?P<req_id>\d+)/action/$',
        views.request_action, name='connection_request_action'),
    url(r'^connection_requests/(?P<req_id>\d+)/download/$',
        views.download_approved_package, name='download_request_package'),
)

misc = patterns(
    '',
    url(r'^network/$',
        views.network_view, name='network_view'),
    url(r'^network/(?P<pk>\d+)/$',
        views.network_view_neighbors, name='network_view_ad'),
)

urlpatterns = isd_patterns + ad_patterns + connection_request_patterns + misc
