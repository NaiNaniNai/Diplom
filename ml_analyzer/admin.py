from django.contrib import admin

from ml_analyzer.models import AnalyzedTraffic


@admin.register(AnalyzedTraffic)
class AnalyzedTrafficAdmin(admin.ModelAdmin):
    list_display = ("id", "src_ip", "label")
    list_display_links = ("id",)
    ordering = ("id",)
