# Generated by Django 5.0.6 on 2024-06-12 11:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_alter_customuser_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='employee_number',
            field=models.CharField(default='DEFAULT_EMPLOYEE_NUMBER', max_length=50, unique=True),
        ),
    ]