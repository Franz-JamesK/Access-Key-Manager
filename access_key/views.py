from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from .models import AccessKey
from authentication.models import CustomUser
from django.contrib.auth import get_user_model
from rest_framework import status

@csrf_exempt
@api_view(['POST'])
def generate_access_key(request):
    if request.method == 'POST':
        email = request.data.get('email')
        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return JsonResponse({'message': 'User not found'}, status=404)

        if AccessKey.objects.filter(user=user, status='active').exists():
            return JsonResponse({'message': 'User already has an active key'}, status=400)

        key = AccessKey.objects.create(user=user)
        key.save()

        return JsonResponse({'message': 'Access key generated successfully', 'key': str(key.key)}, status=201)
    
    return JsonResponse({'message': 'Method not allowed'}, status=405)

@csrf_exempt
@api_view(['GET'])
def list_access_keys(request):
    if request.method == 'GET':
        keys = AccessKey.objects.all()

        if not keys.exists():
            return JsonResponse({'message': 'No keys found'}, status=404)

        keys_data = [
            {
                'key': str(key.key),
                'status': key.status,
                'procurement_date': key.procurement_date,
                'expiry_date': key.expiry_date,
                'user_email': key.user.email  # Include the user's email for context
            } for key in keys
        ]

        return JsonResponse({'keys': keys_data}, status=200)

    return JsonResponse({'message': 'Method not allowed'}, status=405)

@csrf_exempt
@api_view(['POST'])
def revoke_access_key(request):
    if request.method == 'POST':
        user_email = request.data.get('user_email')
        if user_email is None:
            return JsonResponse({'message': 'User email is required'}, status=400)

        try:
            user = CustomUser.objects.get(email=user_email)
            key = AccessKey.objects.filter(user=user, status='active').first()
            if key:
                key.status = 'revoked'
                key.save()
                return JsonResponse({'message': 'Key revoked successfully'}, status=200)
            else:
                return JsonResponse({'message': 'Active key not found'}, status=404)
        except CustomUser.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': f'An error occurred: {str(e)}'}, status=500)
    else:
        return JsonResponse({'message': 'Method not allowed'}, status=405)

@csrf_exempt
@api_view(['GET'])
def get_active_key_status(request, email):
    try:
        # Check if the user with the given email exists
        user = get_user_model().objects.get(email=email)
    except get_user_model().DoesNotExist:
        return JsonResponse({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Check for an active key associated with the user
    key = AccessKey.objects.filter(user=user, status='active').first()

    if key:
        # If an active key is found, return the details
        return JsonResponse({
            'status': key.status,
            'procurement_date': key.procurement_date,
            'expiry_date': key.expiry_date
        }, status=status.HTTP_200_OK)

    # If no active key is found, return a 404 status
    return JsonResponse({'message': 'No active key found'}, status=status.HTTP_404_NOT_FOUND)
