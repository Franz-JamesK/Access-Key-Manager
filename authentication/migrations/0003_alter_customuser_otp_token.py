# Generated by Django 5.0.6 on 2024-05-31 09:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_alter_customuser_options_alter_customuser_managers_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='otp_token',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
    ]