from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth import get_user_model, logout
from django.http import JsonResponse
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.shortcuts import render, get_object_or_404, redirect
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
import logging
from jose import jwt, JWTError
from .models import CustomUser
from .utils import generate_otp
from .validators import validate_password
from smtplib import SMTPException
from django.views.decorators.csrf import csrf_exempt

email_not_found = 'Email not found'
logger = logging.getLogger(__name__)
@csrf_exempt
def send_verification_email(user):
    try:
        token = jwt.encode({'email': user.email}, settings.SECRET_KEY, algorithm='HS256')
        verification_link = f"{settings.SITE_URL}{reverse('verify_email', args=[token])}"
        subject = 'Email Verification'
        message = (
            f'Please click the link to verify your email: {verification_link}\n\n'
            f'Alternatively, you can copy this token and enter it in the verification tab to verify your email:\n\n'
            f'Token: {token}'
        )
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)
        logger.info(f'Verification email sent to {user.email}')
    except BadHeaderError:
        logger.error(f'Invalid header found when sending email to {user.email}')
        raise
    except SMTPException as e:
        logger.error(f'SMTPException occurred when sending email to {user.email}: {e}')
        raise
    except Exception as e:
        logger.error(f'An unexpected error occurred when sending email to {user.email}: {e}')
        raise

def send_otp_email(user, otp_code):
    subject = "Password Reset"
    message = f"Please use this OTP code {otp_code} to reset your password"
    try:
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)
    except (SMTPException, BadHeaderError) as e:
        logger.error(f'Failed to send OTP email to {user.email}: {e}')
        raise
@csrf_exempt
@api_view(['POST'])
def user_registration(request):
    if request.method == 'POST':
        employee_number = request.data.get('employee_number')
        email = request.data.get('email')
        password = request.data.get('password')

        if not employee_number or not email or not password:
            return JsonResponse({'message': 'Missing data in the request.'}, status=400)

        try:
            validate_password(password)
        except ValidationError as e:
            return JsonResponse({'message': str(e)}, status=400)

        if CustomUser.objects.filter(email=email).exists():
            return JsonResponse({'message': 'User with this email already exists.'}, status=401)
        if CustomUser.objects.filter(employee_number=employee_number).exists():
            return JsonResponse({'message': 'User with this employee number already exists.'}, status=402)

        user = CustomUser.objects.create_user(employee_number=employee_number, email=email, password=password)
        user.email_verified = False
        user.save()

        try:
            send_verification_email(user)
        except SMTPException as e:
            return JsonResponse({'message': 'Error sending verification email: {}'.format(str(e))}, status=500)

        return JsonResponse({'message': 'Registration successful. Please check your email for verification link.'}, status=201)

@csrf_exempt
@api_view(['POST'])
def admin_registration(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return JsonResponse({'message': 'Missing data in the request.'}, status=400)

        try:
            validate_password(password)
        except ValidationError as e:
            return JsonResponse({'message': str(e)}, status=400)

        if CustomUser.objects.filter(email=email).exists():
            return JsonResponse({'message': 'User with this email already exists.'}, status=401)

        # Provide a default employee number for admin users
        default_employee_number = 'ADMIN001'

        # Create an admin user with the default employee number
        user = CustomUser.objects.create_superuser(employee_number=default_employee_number, email=email, password=password)
        user.set_password(password)
        user.save()

        send_verification_email(user)
        return JsonResponse({'message': 'Admin registration successful. Please check your email for the verification link.'}, status=201)
@csrf_exempt
@api_view(['POST'])
def user_login(request):
    user_model = get_user_model()
    email = request.data.get('email')
    password = request.data.get('password')
    user = user_model.objects.filter(email=email).first()

    if user and user.check_password(password):
        if not user.email_verified:
            return Response({'message': 'Email not verified.'}, status=status.HTTP_403_FORBIDDEN)
        refresh = RefreshToken.for_user(user)
        response_data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        if user.is_staff or user.is_superuser:
            response_data['dashboard'] = 'admin'
        else:
            response_data['dashboard'] = 'user'
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Invalid login credentials'}, status=status.HTTP_401_UNAUTHORIZED)
@csrf_exempt
@api_view(['POST'])
def user_logout(request):
    logout(request)
    return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
@csrf_exempt
@api_view(['POST'])
def password_reset_request(request):
    user_model = get_user_model()
    email = request.data.get('email')

    if not email:
        return JsonResponse({'message': 'Missing email in the request.'}, status=400)

    try:
        user = user_model.objects.get(email=email)
    except user_model.DoesNotExist:
        return Response({'message': email_not_found}, status=status.HTTP_404_NOT_FOUND)

    otp_code = generate_otp()
    user.otp_token = otp_code
    user.otp_timestamp = timezone.now()
    user.save()

    try:
        send_otp_email(user, otp_code)
    except Exception:
        return Response({'message': 'Failed to send OTP email. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({'message': 'Password reset initiated. Check your email for instructions.'}, status=status.HTTP_200_OK)
@csrf_exempt
@api_view(['POST'])
def verify_otp(request):
    user_model = get_user_model()
    email = request.data.get('email')
    otp = request.data.get('otp')

    try:
        user = user_model.objects.get(email=email)
    except user_model.DoesNotExist:
        return Response({'message': email_not_found}, status=status.HTTP_404_NOT_FOUND)

    if user.otp_token != otp or (timezone.now() - user.otp_timestamp) > timedelta(minutes=10):
        return Response({'message': 'Invalid or expired OTP code'}, status=status.HTTP_401_UNAUTHORIZED)

    user.otp_token = ''
    user.otp_timestamp = None
    user.save()
    return Response({'message': 'OTP verification successful'}, status=status.HTTP_200_OK)
@csrf_exempt
@api_view(['POST'])
def reset_password(request):
    user_model = get_user_model()
    email = request.data.get('email')
    password = request.data.get('password')

    try:
        validate_password(password)
    except ValidationError as e:
        return JsonResponse({'message': str(e)}, status=400)

    try:
        user = user_model.objects.get(email=email)
    except user_model.DoesNotExist:
        return Response({'message': email_not_found}, status=status.HTTP_404_NOT_FOUND)

    user.set_password(password)
    user.save()

    return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
@csrf_exempt
@api_view(['POST'])  # Ensure this supports POST requests
def verify_email(request, token):
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        email = decoded_token.get('email')
    except JWTError:
        return JsonResponse({'message': 'Invalid token'}, status=400)

    user = get_object_or_404(get_user_model(), email=email)
    user.email_verified = True
    user.verification_token = ""
    user.save()
    return JsonResponse({'message': 'Email verified successfully'}, status=200)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request):
    # Authenticate the user using JWT token
    user = request.user
    if not user.is_authenticated:
        return JsonResponse({'error': 'User is not authenticated'}, status=401)
    
    # Determine the user's role based on is_staff and is_superuser fields
    if user.is_superuser:
        role = 'admin'
    elif user.is_staff:
        role = 'staff'
    else:
        role = 'regular user'
    
    # Return user details
    user_data = {
        'id': user.id,
        'email': user.email,
        'role': role  # Using determined role
    }
    
    return JsonResponse(user_data)
