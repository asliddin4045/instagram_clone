from .views import CreateUserView, VerifyAPIView, GetNewVerification,\
    ChangeUserInformationView, ChangeUserPhotoView, LoginView, \
    LoginRefreshView, LogOutView, ForgotPasswordView, ResetPasswordView
from django.urls import path

urlpatterns = [
    path('login/', LoginView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('logout/', LoginView.as_view()),
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyAPIView.as_view()),
    path('new-verify/', GetNewVerification.as_view()),
    path('change-user/', ChangeUserInformationView.as_view()),
    path('change-user-photo/', ChangeUserPhotoView.as_view()),
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view()),
]