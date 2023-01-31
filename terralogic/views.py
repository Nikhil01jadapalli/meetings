from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from urllib import response
from rest_framework import generics, status 
from .serializers import RegisterSerializer
from rest_framework.response import Response  
from rest_framework.decorators import authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import User,Roomuser
import jwt , datetime
from django.conf import settings
from .serializers import *
from rest_framework.views import APIView
from django.core.mail import send_mail
# from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework.decorators import permission_classes,api_view
# Create your views here.

@api_view(["POST"])
# @permission_classes([AllowAny])
# serializer_class = RegisterSerializer
def Register(request):
    serializer_class = RegisterSerializer
    user = request.data
    serializer = serializer_class(data=user)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    user_data = serializer.data
    user = User.objects.get(email=user_data['email']) 
    # token = RefreshToken.for_user(user).access_token
    # current_site = get_current_site(request).domain
    # # relativeLink = reverse('email-verify')
    # relativeLink = reverse('login')
    # absurl = 'http://'+current_site+relativeLink
    # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
    email_body = 'Hi '+user.username  +'\n Thank you for registering with Terralogic Meet. Please find the credentials below for your future reference.\n '+ \
        ' Use the link below to verify your email \n'+'\n Username :'+user.username + '\n Password :'+'*********'  + \
            "\n URl:"+ '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                '\n Thanks,' +'\n Terralogic Team'            
    data = {'email_body': email_body, 'to_email': user.email,
            'email_subject': 'Registration successfull'}
    subject='Registration successfull'
    message=f' {email_body}'
    email_from=settings.EMAIL_HOST_USER
    recipient_list=[user.email]
    if user:
        Email=send_mail(subject,message,email_from,recipient_list)
        user.Email=Email
        user.save()
    else:
        return response('failed')


    return Response(user_data,status=status.HTTP_201_CREATED)

    

@api_view(["POST"])


def login(request):
    email = request.data['email']
    password = request.data['password']

    user = User.objects.filter(email=email).first()

    if user is None:
        raise AuthenticationFailed('User not found!')

    if not user.check_password(password):
        raise AuthenticationFailed('Incorrect password!')

    payload = {
        'id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        'iat': datetime.datetime.utcnow()
    }

    token = jwt.encode(payload, 'secret', algorithm='HS256')

    response = Response()

    response.set_cookie(key='jwt', value=token, httponly=True)
    response.data = {
        'jwt': token,
        'username':user.username
    }
    return response



# class MeetingView(generics.GenericAPIView):

    # serializer_class = MeetingSerializer
@api_view(["POST"])   
def post(self, request):
        email = request.data.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            Link = request.data.get('Link', '')
            absurl = Link 
            email_body = 'Hi'+ user.username+'\n' + 'Use below link to join meeting  \n' + \
                absurl+'\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                    '\n Thanks,' +'\n Terralogic Team' 
            data = {'email_body': email_body, 'to_email': user.email,}

            # serializer = self.serializer_class(data=request.data)
            # if  not serializer.is_valid():
                # return response(serializer.ERROR,status=status.HTTP_400_BAD_REQUEST)
            subject='Invitation For Terralogic Meet'
            message=f' {email_body}'
            email_from=settings.EMAIL_HOST_USER
            recipient_list=[user.email]
            if user:
                Email=send_mail(subject,message,email_from,recipient_list)
                user.Email=Email
                user.save()
            else:
                return response('failed')
        else:

            Link = request.data.get('Link', '')
            absurl = Link
            email_body = 'Hi,'+'\n' + 'Use below link to join meeting  \n' + \
                absurl +'\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                    '\n Thanks,' +'\n Terralogic Team' 
            data = {'email_body': email_body, 'to_email': email,}
            subject='Invitation For Terralogic Meet'
            message=f' {email_body}' 
            email_from=settings.EMAIL_HOST_USER
            recipient_list=[email]
             
            Email=send_mail(subject,message,email_from,recipient_list)
            Email=Email
 
             
 
        return Response({'success': 'We have sent you a link for attend meeting'}, status=status.HTTP_200_OK) 




@api_view(["GET", "POST"])
# @authentication_classes((JWTAuthentication,))
@permission_classes((AllowAny, ))
def room_list(request):
    if request.method == "GET":
        search = request.query_params.get("search", None)
        if search is not None:
            rooms = Room.objects.filter(title__icontains=search).order_by("-created_on")
        else:
            rooms = Room.objects.all().order_by("-created_on")
        serializer = RoomSerializer(rooms, many=True)
        return Response(serializer.data)

    elif request.method == "POST":
        serializer = RoomSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAuthenticated])
def room_detail(request, pk):
    try:
        room = Room.objects.get(pk=pk)
    except Room.DoesNotExist:
        return Response({"message": "Room not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = RoomSerializer(room)
        return Response(serializer.data)

    if request.method == "PUT":
        serializer = RoomSerializer(room, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == "DELETE":
        authenticate_class = JWTAuthentication()
        user,   _ = authenticate_class.authenticate(request)
        if user.id == room.user.id:
            room.delete()
            return Response({}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response(
                {"message": "Either you are not logged in or you are not the owner of this room to delete"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


@api_view(['POST'])
# @authentication_classes((UserJSONWebTokenAuthentication, ))
# @permission_classes((IsAuthenticated, ))
def Add_user_to_room(request):
    try:
        data=request.data
        user = data.get('user')
        Room = data.get('room')

        room_user_existing = Roomuser.objects.filter(
            user=user,Room=Room).count()
        if room_user_existing:
            local_reponse = Response({"message": "Already Added."},status=status.HTTP_400_BAD_REQUEST)
            return local_reponse
        temp={}
        temp['user']= user
        temp['Room']= Room
        serializers = RoomuserSerializer(data=temp)
        if not serializers.is_valid():
            return Response({"message": serializers.error_messages},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializers.save()
        local_response = Response({"message": "User Added."},
                status=status.HTTP_201_CREATED,
                data=serializers.data

            )
        return local_response
    except User.DoesNotExist as e:
        return Response(
            code=400,
            data=[],

        )



# @authentication_classes((UserJSONWebTokenAuthentication, ))
# @permission_classes((IsAuthenticated, ))
@api_view(['DELETE']) 
def Delete_user(request, id):
    
    try:
        user = Roomuser.objects.get(id=id)
    except Roomuser.DoesNotExist:
        return response({"message": "Does not exist."},
                status=status.HTTP_400_BAD_REQUEST,
                )
    roomuser= Roomuser.objects.filter(id=id)
    roomuser.delete()
    return Response({"messege":"deleted"},status=status.HTTP_204_NO_CONTENT)
