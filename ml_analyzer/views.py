from datetime import datetime
import os

from django.contrib.sites.models import Site
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

from ml_analyzer.service import ReaderPcapFile
from project_root.settings import CURRENT_HOST


# Create your views here.
class Test(View):
    def get(self, request):
        current_directory = os.path.dirname(os.path.abspath(__file__))
        pcap_files_directory = "pcap_files/"
        date = datetime.date(datetime.now())
        daily_save_directory = pcap_files_directory + f"{date}/"
        save_directory = daily_save_directory
        absolute_url_save_directory = current_directory + "/" + save_directory
        service = ReaderPcapFile()
        service.run(absolute_url_save_directory)
        return JsonResponse({"200": "Ok"})
