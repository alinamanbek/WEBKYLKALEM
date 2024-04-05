
'''
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),

    # Include your app's URLs
    path('', include('main.urls')),

    # Include rest_framework_simplejwt URLs
    path('api/token/', include('rest_framework_simplejwt.urls')),
]
'''
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('main.urls')),  # Include users app's URL patterns
]
