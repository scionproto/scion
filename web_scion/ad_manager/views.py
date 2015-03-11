from django.http import JsonResponse
from django.views.generic import ListView, DetailView
from ad_manager.models import AD, ISD


class ISDListView(ListView):
    model = ISD


class ISDDetailView(DetailView):
    model = ISD


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']
        context['routers'] = ad.routerweb_set.select_related().all()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        return context


def get_ad_status(request, pk):
    ad = AD.objects.get(id=pk)
    ad_info = ad.query_ad_status()
    return JsonResponse({'data': ad_info})

