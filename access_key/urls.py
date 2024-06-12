from django.urls import path
from .views import generate_access_key, list_access_keys, revoke_access_key, get_active_key_status

urlpatterns = [
    path('generate-key/', generate_access_key, name='generate_key'),
    path('list-keys/', list_access_keys, name='list_keys'),
    path('revoke-key/', revoke_access_key, name='revoke_key'),
    path('active-key-status/<str:email>/', get_active_key_status, name='active_key_status'),
]
