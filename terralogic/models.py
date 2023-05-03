from django.db import models
# from django.contrib.auth.models import user
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
        # user.check_password = True
        user.save()
        return user

AUTH_PROVIDERS = {'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    # name = models.CharField(max_length=50 ,blank=True)
    # user = models.OneToOneField(user,on_delete=models.CASCADE)
    forget_password_token =models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    link=models.URLField()
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))
    


    USERNAME_FIELD = 'email'
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

    meeting_id =models.CharField(max_length=200)
    created_on = models.DateTimeField(auto_now_add=True)




class meeting_candidate(models.Model):
    meeting_id =models.ForeignKey(Room, related_name ="meeeting_id",on_delete=models.CASCADE)
    candidate_id=models.ForeignKey(User, related_name ="candidate_id",on_delete=models.CASCADE)
    accepted = models.CharField(max_length=50, blank=True)
    owner = models.CharField(max_length=50,blank=True,null=True) 
    


    

# class forgetpassword(models.Model):
#     email = models.ForeignKey(User, related_name ="meeeting_id",on_delete=models.CASCADE)
#     # user =models.ForeignKey(User, related_name ="username",on_delete=models.CASCADE)
#     forget_password_token =models.CharField(max_length=100)
#     created_at = models.DateTimeField(auto_now_add=True)
#     new_password =models.CharField(max_length=100)





# class MeetingParticipant(models.Model):
#     Room = models.ForeignKey(Room,related_name='Room',on_delete=models.CASCADE)
#     participants = models.CharField(max_length=80)
#     # user_id
#     username=models.ForeignKey(User,related_name='username',on_delete=models.CASCADE)
#     email =models.ForeignKey(User,related_name='email',on_delete=models.CASCADE)
#     owener =models.CharField( max_length=50)






