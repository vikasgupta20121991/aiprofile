from django.urls import path
from .views.authviews import (RegisterUser, LoginUser, ForgotPasswordView, 
                              ForgotPasswordOtpView, ResetPasswordView, RolesListView, 
                              VerifyEmailOtpView, UserView, SuperUserLogin,
                              VerifyOTPAPIView,ResendOTPView)
from .views.emailviews import *

urlpatterns = [
  
    path('register/', RegisterUser.as_view(), name='register'),
    path('getroles/', RolesListView.as_view(), name='getroles'),
    
    path('login/', LoginUser.as_view(), name='login'),
    path('superuserlogin/', SuperUserLogin.as_view(), name='login'),
    
    path('verify-otp/', VerifyOTPAPIView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    
    path('<int:id>/', UserView.as_view(), name='userview'),
    
    path('forgotpassword/', ForgotPasswordView.as_view(), name='forgotpassword'),
    path('resetpassword/', ResetPasswordView.as_view(), name='resetpassword'),
    
    
    
    
    
    
    path('verifyemail-otp/', VerifyEmailOtpView.as_view(), name='verifyemail-otp'),
    path('forgotpassword-otp/', ForgotPasswordOtpView.as_view(), name='forgotpasswordotp'),
    
    


    path('email/', varification_mail, name='email'),

]
