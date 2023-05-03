from django.shortcuts import render
from urllib import response
from rest_framework import generics, status
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework.decorators import authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import User,Room
import jwt , datetime
from django.conf import settings
from .serializers import *
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
from django.urls import reverse
# from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import ResetPassWordSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.decorators import permission_classes,api_view
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str,smart_bytes,force_bytes, DjangoUnicodeDecodeError
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
    Login_Url = request.data.get('Link', '')
    link = Login_Url
    # token = RefreshToken.for_user(user).access_token
    # current_site = get_current_site(request).domain
    # # relativeLink = reverse('email-verify')
    # relativeLink = reverse('login')
    # absurl = 'http://'+current_site+relativeLink
    # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
    email_body = 'Hi '+user.username  +'\nThank you for Registering with Terralogic Meet. Please find the credentials below for your future reference.\n '+ '\n Use the below link to login terralogic meet \n'+" Login_url:"+link + '\n \n Username :'+user.username + '\n Password :'+'********* \n'  + '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
    '\n Thanks,' +'\n Terralogic Team'
    data = {'email_body': email_body, 'to_email': user.email,
            'email_subject': 'Registration Successfull'}
    subject='Registration Successfull'
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
        return Response({"Email:invalid email "},status=status.HTTP_401_UNAUTHORIZED)
        # raise AuthenticationFailed('User not found!')

    if not user.check_password(password):
        return Response({"Password:invalid password"},status=status.HTTP_404_NOT_FOUND)
        # raise AuthenticationFailed('Incorrect password!')

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
def meeting_mail(request):
        email = request.data.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            Link = request.data.get('Link', '')
            absurl = Link
            email_body = 'Hi '+ user.username+'\n' + 'Use below link to join meeting  \n' + \
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
        meeting_id= {"meeting_id":"" + str(uuid4().hex)}
        serializer = RoomSerializer(data=meeting_id)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["GET", "PUT", "DELETE"])
# @permission_classes([IsAuthenticated])
def room_detail(request, id):
    try:
        room = Room.objects.get(id=id)
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
        candidate_id = data.get('candidate_id')
        meeting_id = data.get('meeting_id')
        owner = data.get("owner")
        accepted =data.get('accepted')
        room_user_existing = meeting_candidate.objects.filter(
            candidate_id=candidate_id,meeting_id=meeting_id).count()
        if room_user_existing:
            local_reponse = Response({"message": "Already Added."},status=status.HTTP_400_BAD_REQUEST)
            return local_reponse
        temp={}
        temp['candidate_id']= candidate_id
        temp['meeting_id']= meeting_id
        temp['owner']= owner
        temp['accepted']= accepted
        serializers = RoomuserSerializer(data=temp)
        if not serializers.is_valid():
            return Response({"message": serializers.error_messages},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializers.save()
        local_response = Response(
                status=status.HTTP_201_CREATED,
                data=serializers.data

            )
        return local_response
    except User.DoesNotExist as e:
        return Response(
            code=400,
            data=[])

@api_view(["GET"])
def room_user_list(request,room_id):
    users =meeting_candidate.objects.filter(meeting_id=room_id).values("candidate_id","owner")
    meet_room=  Room.objects.get(id=room_id)
    room_data=[]
    for user in users:
        temp= {}
        userobj = User.objects.get(id= user.get('candidate_id'))
        # print(userobj)
        temp['user_id'] = userobj.id
        temp['username'] = userobj.email
        temp["name"]= userobj.username
        temp['owener']= user.get('owner')
        room_data.append(temp)
        response = {'meeting_id':room_id,"meeting_room_id":meet_room.meeting_id,"participents":room_data}
    return Response(
            status=status.HTTP_201_CREATED,
            data=response

        )




@api_view(['POST'])
def request_password_reset_email(request):
    email = request.data.get('email')
    if email:
        user = get_object_or_404(User, email=email)
        token = PasswordResetTokenGenerator().make_token(user)
        # uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        # current_site = get_current_site(
        #         request=request).domain
        # relativeLink = reverse(
        #         'password', kwargs={'uidb64': uidb64, 'token': token})

        redirect_url = request.data.get('redirect_url', '')
        # absurl = 'http://'+current_site + relativeLink

        # current_site = get_current_site(request)
        # reset_url = reverse('password', kwargs={'uidb64': uidb64, 'token': token})
        # reset_url = 'http://' + current_site.domain + reset_url

        subject = 'Password Reset Requested'
        # email_message = f'Hi {user.username},\n\nPlease use the link below to reset your password:\n\n{reset_url}+?redirect_url={redirect_url} \n\nIf you did not request this reset, please ignore this message.'
        email_message = f'Hi {user.username},\n\nPlease use the link below to reset your password:\n\nLink={redirect_url} \nIf you did not request this reset, please ignore this message.'
        data = {'email_body': email_message, 'to_email': email,}
        message=f' {email_message}'
        email_from=settings.EMAIL_HOST_USE
        recipient_list=[email]
        Email=send_mail(subject,message,email_from,recipient_list)
        # send_mail(
        #     email_subject,
        #     email_message,
        #     settings.DEFAULT_FROM_EMAIL,
        #     [user.email],
        #     fail_silently=False,
        # )
        res = {
                'token':token,
                'uidb64':uidb64
            }
        return Response({"data":{
            'token': token,
            'uidb64':uidb64}},
            status=status.HTTP_200_OK,
    )
    # return Response({'success': 'Please check your email to reset your password.'}, status=status.HTTP_200_OK)


# from django.utils.encoding import smart_str
# from django.utils.http import urlsafe_base64_decode
# from rest_framework import status
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.contrib.auth.models import User

# @api_view(['GET'])
# def password_token_check(uidb64, token):
#     try:
#         id = smart_str(urlsafe_base64_decode(uidb64))
#         user = User.objects.get(id=id)
#         token_value =token
#         if not PasswordResetTokenGenerator().check_token(user,token_value):
#             return Response({'error': 'token is not valid, please check the new one'},
#                             status=status.HTTP_401_UNAUTHORIZED)
#         return Response({'sucess': True, 'message': 'Credential Valid', 'uidb64': uidb64, 'token': token},
#                         status=status.HTTP_200_OK)
#     except Exception as e:
#         return Response({'error': 'token is not valid, please check the new one'},
#                         status=status.HTTP_401_UNAUTHORIZED)
@api_view(['GET'])
def password_token_check(request, uidb64, token):
    try:
        id = int(urlsafe_base64_decode(uidb64).decode())
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({'error': 'Token is not valid, please request a new one.'},
                            status=status.HTTP_401_UNAUTHORIZED)
        return Response({'success': True, 'message': 'Credential Valid', 'uidb64': uidb64, 'token': token},
                        status=status.HTTP_200_OK)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'error': 'Token is not valid, please request a new one.'},
                        status=status.HTTP_401_UNAUTHORIZED)



from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import ResetPassWordSerializer
# from django.contrib.auth.models import User

@api_view(['PATCH'])
def set_new_password(request):
    queryset = User.objects.all()
    serializer_class = ResetPassWordSerializer

    serializer = serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)

    return Response({'success': True, 'message': 'Password is reset successfully'}, status=status.HTTP_200_OK)
