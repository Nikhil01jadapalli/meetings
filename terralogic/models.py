from django.db import models

# Create your models here.
from django.db import models
from django.contrib import admin
# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                   'twitter': 'twitter', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    # is_verified = models.BooleanField(default=False)
    # is_active = models.BooleanField(default=True)
    # is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    userformail = models.EmailField( max_length=255,blank=True)
    link=models.URLField()
    # idforuser=models.CharField(max_length=255)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))
    
 

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []



        
    objects = UserManager()



    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }




class Room(models.Model):

    """
    Room Model for group calling
    """
 
    ROOM_TYPE = [
        ("OTA", "Open to all"),
        ("IO", "Invite only"),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    # answerCandidates = models.CharField(max_length=255,  db_index=True)

    title = models.CharField(max_length=200)
    type_of = models.CharField(
        max_length=3,
        choices=ROOM_TYPE,
        default="OTA",
    )
    created_on = models.DateTimeField(auto_now_add=True)

    


class Roomuser(models.Model):
    user =models.ForeignKey(User, related_name= "user_id", blank=True,null=True, on_delete=models.CASCADE)
    Room = models.ForeignKey(Room, related_name="Room_id",blank=True,null=True,on_delete=models.CASCADE)

