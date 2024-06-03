from django.urls import path

from ml_analyzer.views import Test

urlpatterns = [
    path('', Test.as_view()),
]
