from django.urls import path
# from .views import Register


from terralogic import views as meet_view

urlpatterns = [
    # path('register',view=meet_view.Register, name="register"),
    # path('login', view=meet_view.login, name="login"),
    # path('roomlist', view=meet_view.room_list, name="room"),
    # path('adduser', view=meet_view.Add_user_to_room, name="addusertoroom"),
    # path('deleteuser/<int:id>', view=meet_view.Delete_user, name="addusertoroom"),
    path('register',view=meet_view.Register, name="register"),
    path('login', view=meet_view.login, name="login"),
    path('meeting_mail',view=meet_view.meeting_mail,name="meeting_mail"),
    path('roomlist', view=meet_view.room_list, name="room"),
    path('roomdetails/<int:id>', view=meet_view.room_detail, name="room"),
    path('adduser', view=meet_view.Add_user_to_room, name="addusertoroom"),
    path('meetdetails/<int:room_id>', view=meet_view.room_user_list, name="meetdetails"),
    path('password/<uidb64>/<token>/',view=meet_view.password_token_check, name='password'),
    path('reset/',view=meet_view.request_password_reset_email, name='reset'),
    path('change/',view=meet_view.set_new_password, name='change')

]
