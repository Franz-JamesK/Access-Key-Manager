import secrets
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Permission, Group
from django.db import models
import jwt
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class CustomUserManager(BaseUserManager):
    def create_user(self, employee_number, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(employee_number=employee_number, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, employee_number, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(employee_number, email, password, **extra_fields)

    def create_user_with_token(self, employee_number, email, password=None, **extra_fields):
        user = self.create_user(employee_number, email, password, **extra_fields)
        user.verification_token = jwt.encode({'email': user.email, 'exp': timezone.now() + timedelta(days=1)}, settings.SECRET_KEY, algorithm='HS256')
        user.save()
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    employee_number = models.CharField(max_length=50, unique=True, default='DEFAULT_EMPLOYEE_NUMBER')
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=64, default=secrets.token_urlsafe)
    token = models.CharField(max_length=100, blank=True)
    otp_token = models.CharField(max_length=6, blank=True, null=True)
    otp_timestamp = models.DateTimeField(blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['employee_number']

    def __str__(self):
        return self.email

    user_permissions = models.ManyToManyField(Permission, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
