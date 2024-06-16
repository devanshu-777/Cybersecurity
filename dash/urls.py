from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns=[
    path('scan_view/<str:ip_address>', views.scan_view,name='nmapscan'),
]