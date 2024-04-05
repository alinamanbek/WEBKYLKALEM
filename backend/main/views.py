# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login
# from rest_framework.authtoken.models import Token
 
 
# @api_view(['POST'])
# def register(request):
#     if request.method == 'POST':
#         username = request.data.get('username')
#         email = request.data.get('email')
#         password = request.data.get('password')
#         user_type = request.data.get('user_type')  # Assuming you pass user_type in the request data
        
#         if not username or not email or not password or not user_type:
#             return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Check if username or email already exists
#         if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
#             return Response({'error': 'Username or email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Create the user
#         user = User.objects.create_user(username=username, email=email, password=password)
        
#         # Additional logic for user type
#         if user_type == 'admin':
#             # Create admin profile or do any additional logic
#             pass
#         elif user_type == 'painter':
#             # Create painter profile or do any additional logic
#             pass
#         elif user_type == 'customer':
#             # Create customer profile or do any additional logic
#             pass
        
#         return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)


# @api_view(['POST'])
# def login(request):
#     if request.method == 'POST':
#         username = request.data.get('username')
#         password = request.data.get('password')
        
#         if not username or not password:
#             return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Authenticate user
#         user = authenticate(username=username, password=password)
        
#         if user:
#             # Generate or retrieve token
#             token, created = Token.objects.get_or_create(user=user)
#             return Response({'token': token.key}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from django.contrib.auth.models import User
# from .models import Admin, Painter, Customer
# from django.contrib.auth import authenticate, login
# from rest_framework.authtoken.models import Token

# @api_view(['POST'])
# def register(request):
#     if request.method == 'POST':
#         username = request.data.get('username')
#         email = request.data.get('email')
#         password = request.data.get('password')
#         user_type = request.data.get('user_type')

#         if not (username and email and password and user_type):
#             return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

#         if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
#             return Response({'error': 'Username or email already exists'}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.create_user(username=username, email=email, password=password)
        
#         # Additional logic for user type
#         if user_type == 'admin':
#             Admin.objects.create(user=user)
#         elif user_type == 'painter':
#             Painter.objects.create(user=user)
#         elif user_type == 'customer':
#             Customer.objects.create(user=user)
        
#         return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

# @api_view(['POST'])
# def login(request):
#     if request.method == 'POST':
#         username = request.data.get('username')
#         password = request.data.get('password')
        
#         if not username or not password:
#             return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Authenticate user
#         user = authenticate(username=username, password=password)
        
#         if user:
#             # Generate or retrieve token
#             token, created = Token.objects.get_or_create(user=user)
#             return Response({'token': token.key}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

from django.http import HttpResponse
from django.urls import reverse
from .models import Painter, Customer
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
 
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import render, redirect
 
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .forms import PasswordResetForm  # Import the PasswordResetForm


@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        # Assuming you receive registration data in the request
        registration_data = request.data  # Example
        
        # Process registration data and create User instance
        user = User.objects.create_user(username=registration_data['username'], email=registration_data['email'], password=registration_data['password'])
        
        # Check the user_type
        user_type = registration_data.get('user_type')
        if user_type == 'painter':
            # If user_type is painter, create a Painter instance
            painter_data = request.data  # Example painter data
            painter = Painter.objects.create(user=user)
            return Response({'message': 'Painter created successfully'}, status=status.HTTP_201_CREATED)
        elif user_type == 'customer':
            # If user_type is customer, create a Customer instance
            customer_data = request.data  # Example customer data
            customer = Customer.objects.create(user=user)
            return Response({'message': 'Customer created successfully'}, status=status.HTTP_201_CREATED)
        else:
            # If user_type is not specified, just return a success response
            login_link = reverse('login')  # Assuming you have a URL pattern named 'login' for the login page
            message = 'User registered successfully. Please <a href="{}">log in</a>.'.format(login_link)
            return Response({'message': message}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        
        if user:
            # Generate or retrieve token
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'message': 'Logged in successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

token_generator = PasswordResetTokenGenerator()

def reset_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            # Process form data and reset password
            # Assuming you have the logic to reset the password here
            return redirect('login')  # Redirect to login page after successful password reset
    else:
        form = PasswordResetForm()
    return render(request, 'reset_password_form.html', {'form': form})

def reset_password_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        # Token is valid, display password reset form
        if request.method == 'POST':
            form = PasswordResetForm(request.POST)
            if form.is_valid():
                # Set new password and redirect to login page
                user.set_password(form.cleaned_data['password'])
                user.save()
                return redirect('login')  # Redirect to login page after successful password reset
        else:
            form = PasswordResetForm()
        return render(request, 'reset_password_form.html', {'form': form})
    else:
        # Invalid token, show an error message
        return render(request, 'password_reset_invalid_token.html')


from django.core.mail import send_mail
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Check if the email exists in the database
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User with this email does not exist'}, status=400)

        # Generate a password reset token
        token = default_token_generator.make_token(user)

        # Construct the password reset link
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = reverse('reset_password_confirm', kwargs={'uidb64': uidb64, 'token': token})
        reset_link = request.build_absolute_uri(reset_url)

        # Send the reset link to the user's email
        send_mail(
            'Password Reset Request',
            f'Hello,\n\nYou requested a password reset for your account. '
            f'Please click the following link to reset your password:\n\n{reset_link}',
            'your@example.com',  # Sender's email address
            [email],  # List of recipient(s)
            fail_silently=False,
        )

        return JsonResponse({'message': 'Password reset link has been sent to your email'}, status=200)

    return JsonResponse({'error': 'Invalid request method'}, status=405)
