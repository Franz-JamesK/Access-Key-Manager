from django.urls import path
from .views import initialize_payment

urlpatterns = [
    path('initialize/', initialize_payment, name='initialize_payment'),

]
