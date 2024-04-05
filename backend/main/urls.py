
from django.urls import path
from .views import register, login,reset_password, reset_password_confirm,forgot_password

urlpatterns = [
    path('api/register/', register, name='register'),
    path('api/login/', login, name='login'),
    path('reset-password/', reset_password, name='reset_password'),
    path('reset-password/<uidb64>/<token>/', reset_password_confirm, name='reset_password_confirm'),
    path('api/forgot-password/', forgot_password, name='forgot_password'),  # Add this line for the forgot password endpoint

 
]
 

 
  
