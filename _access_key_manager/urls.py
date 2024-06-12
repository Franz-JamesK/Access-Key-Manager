from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('keys/', include('access_key.urls')),
    path('payments/', include('payments.urls')),
]
