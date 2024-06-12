from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid

class AccessKey(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
    ]

    key = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    procurement_date = models.DateTimeField(default=timezone.now)
    expiry_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.email} - {self.status}"

    def save(self, *args, **kwargs):
        if self.status == 'active' and not self.expiry_date:
            self.expiry_date = self.procurement_date + timezone.timedelta(days=365)  # Example: 1-year validity
        super().save(*args, **kwargs)
