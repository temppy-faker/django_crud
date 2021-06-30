from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

urlpatterns = [
    path('auth/register', views.UserSingUpView.as_view(), name='register'),
    path('auth/login', views.UserLoginView.as_view(), name='login'),
    # path('auth/login', views.MyTokenObtainPairView.as_view(), name='login'),
    path('auth/login/reset_password', views.ResetPasswordAPIView.as_view(), name='reset_password'),
    path('auth/resend_email', views.ResendEmailView.as_view(), name='resend_email'),
    path('auth/token-refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/user', views.UserInfoAPIView.as_view(), name='user_info'),
    path('user/verify_email', views.VerifyEmailView.as_view(), name='verify_email'),
    path('user/upload_avatar', views.UploadAvatar.as_view(), name='upload_avatar'),
    path('user/reset_password_email', views.ResetPasswordEmailAPIView.as_view(), name='reset_password_email'),
    path('user/request_role', views.RequestRoleView.as_view(), name='request_role'),
    path('user/change_password', views.ChangePasswordAPIView.as_view(), name='change_password'),
]

urlpatterns += router.urls

