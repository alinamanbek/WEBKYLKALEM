'''from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user),
    path('login/', views.obtain_auth_token),
]'''
from django.urls import path
from .views import register, login

urlpatterns = [
    path('api/register/', register, name='register'),
    path('api/login/', login, name='login'),
]
