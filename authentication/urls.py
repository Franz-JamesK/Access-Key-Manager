from django.urls import path
from .views import admin_registration, user_registration, user_login, user_logout, password_reset_request, verify_otp, reset_password, verify_email, get_user

urlpatterns = [
    path('admin-register/', admin_registration, name='register'),
    path('user-register/', user_registration, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('password-reset/', password_reset_request, name='password_reset'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('reset-password/', reset_password, name='reset_password'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('get-user/', get_user, name='get_user'),
]
