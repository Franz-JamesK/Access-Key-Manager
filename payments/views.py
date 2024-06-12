import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from access_key.models import AccessKey
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes


@csrf_exempt
@api_view(['POST'])
def initialize_payment(request):
    data = JSONParser().parse(request)
    email = data.get('email')
    amount = data.get('amount')

    # Check if email and amount are provided
    if not email or not amount:
        return JsonResponse({'error': 'Email and amount are required.'}, status=400)
    
    try:
        amount = int(amount) 
    except ValueError:
        return JsonResponse({'error': 'Amount must be a valid number.'}, status=400)

    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "email": email,
        "amount": amount
    }

    response = requests.post('https://api.paystack.co/transaction/initialize', headers=headers, json=data)

    if response.status_code == 200:
        response_data = response.json()
        return JsonResponse(response_data)
    else:
        return JsonResponse(response.json(), status=response.status_code)


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request):
    # Authenticate the user using JWT token
    user = request.user
    if not user.is_authenticated:
        return JsonResponse({'error': 'User is not authenticated'}, status=401)
    
    # Return user details
    user_data = {
        'id': user.id,
        'email': user.email,
        'role': user.role  # Ensure you have a role field in your User model
    }
    
    return JsonResponse(user_data)
