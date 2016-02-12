# External packages
from django.conf import settings
from django.core.urlresolvers import reverse


def account_urls(request):
    return {'login_url': settings.LOGIN_URL,
            'logout_url': reverse('logout')}
