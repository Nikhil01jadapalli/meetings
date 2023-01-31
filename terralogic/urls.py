from django.urls import path
# from .views import Register


from terralogic import views as meet_view

urlpatterns = [
    path('register',view=meet_view.Register, name="register"),
    path('login', view=meet_view.login, name="login"),
    path('roomlist', view=meet_view.room_list, name="room"),
    path('adduser', view=meet_view.Add_user_to_room, name="addusertoroom"),
    path('deleteuser/<int:id>', view=meet_view.Delete_user, name="addusertoroom")

]