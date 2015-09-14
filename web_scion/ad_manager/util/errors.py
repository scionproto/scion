# External packages
from django.http import HttpResponse


class HttpResponseUnavailable(HttpResponse):
    status_code = 503
