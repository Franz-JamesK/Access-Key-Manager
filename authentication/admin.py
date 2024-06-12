from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser

    fieldsets = (
        (None, {'fields': ('employee_number', 'email', 'password', 'email_verified', 'verification_token', 'otp_token', 'otp_timestamp')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'user_permissions', 'groups')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('employee_number', 'email', 'password1', 'password2'),
        }),
    )
    list_display = ('email', 'employee_number', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active', 'groups')
    search_fields = ('email', 'employee_number')
    ordering = ('email',)

admin.site.register(CustomUser, CustomUserAdmin)
