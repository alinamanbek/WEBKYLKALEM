 

 
'''
from django.db import models
from django.contrib.auth.models import AbstractUser

class Painter(models.Model):
    user = models.OneToOneField(AbstractUser, on_delete=models.CASCADE)
    createdTime = models.DateTimeField(auto_now_add=True)
    photoUrl = models.URLField()
    AboutPainter = models.TextField()
    workExperience = models.TextField()
    education = models.TextField()

class Client(models.Model):
    user = models.OneToOneField(AbstractUser, on_delete=models.CASCADE)
    createdTime = models.DateTimeField(auto_now_add=True)
    photoUrl = models.URLField()
    PhoneNumber = models.CharField(max_length=20)

class Paint(models.Model):
    name = models.CharField(max_length=255)
    createdTime = models.DateTimeField(auto_now_add=True)
    painter = models.ForeignKey(Painter, on_delete=models.CASCADE)
    photoUrl = models.URLField()
    genre = models.CharField(max_length=100)

class Admin(models.Model):
    user = models.OneToOneField(AbstractUser, on_delete=models.CASCADE)
    createdTime = models.DateTimeField(auto_now_add=True)

class Order(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    painting = models.ForeignKey(Paint, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    painter = models.ForeignKey(Painter, on_delete=models.CASCADE)

class Notification(models.Model):
    painter = models.ForeignKey(Painter, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    createdTime = models.DateTimeField(auto_now_add=True)
    bodyText = models.TextField()
    phoneNumber = models.CharField(max_length=20)

'''
from django.contrib.auth.models import User
from django.db import models

class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_time = models.DateTimeField(auto_now_add=True)

class Painter(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_time = models.DateTimeField(auto_now_add=True)
    photo_url = models.URLField()
    about_painter = models.TextField()
    work_experience = models.TextField()
    education = models.TextField()

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_time = models.DateTimeField(auto_now_add=True)
    photo_url = models.URLField()
    phone_number = models.CharField(max_length=20)
