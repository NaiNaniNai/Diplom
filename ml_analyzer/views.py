from django.contrib.sites.models import Site
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

from project_root.settings import CURRENT_HOST


# Create your views here.
class Test(View):
    def get(self, request):
        current_site = CURRENT_HOST
        print(current_site)
        return JsonResponse()
