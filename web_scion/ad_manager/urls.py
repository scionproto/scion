from django.conf.urls import patterns, url
from ad_manager import views


urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
)