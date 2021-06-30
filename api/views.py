from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.hashers import check_password
from django.contrib.auth import authenticate
from django.shortcuts import redirect
from rest_framework import generics, permissions, status, viewsets, serializers
from rest_framework_simplejwt.serializers import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from django.db import IntegrityError
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_text
from django.utils.six import text_type
from api.models import User
from api.serializers import UserSerializer, CreateUserSerializer
from api.constant import ACCOUNT_NOT_FOUND, EMAIL_NOT_VERIFIED, PASSWORD_NOT_MATCH
from api.utils import TokenGenerator
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from rest_auth.registration.views import SocialLoginView
from django.core.files.base import ContentFile
import base64
import datetime
import os
from linkedin_v2 import linkedin


class UserLoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request, *args, **kwargs):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.get(email=email)

        if user is None:
            raise serializers.ValidationError(ACCOUNT_NOT_FOUND)
        else:
            if user.is_email_verified is False:
                raise serializers.ValidationError(EMAIL_NOT_VERIFIED)
            if check_password(password, user.password) is False:
                raise serializers.ValidationError(PASSWORD_NOT_MATCH)
            else:
                user = authenticate(**{
                    'email': email,
                    'password': password,
                })

                refresh = RefreshToken.for_user(user)

                data = {
                    'email': email,
                    'refresh': text_type(refresh),
                    'access': text_type(refresh.access_token),
                }

                return Response(data=data, status=status.HTTP_200_OK)


class UserInfoAPIView(generics.RetrieveAPIView, generics.UpdateAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        user = request.user
        user.first_name = request.data['first_name']
        user.last_name = request.data['last_name']
        user.title = request.data['title']
        user.save()

        if user.email != request.data['email']:
            email = request.data['email']
            try:
                name = user.first_name + ' ' + user.last_name
                email_verification_url = '%s/api/user/verify_email?uid=%s&email=%s&token=%s' % (
                    request.build_absolute_uri('/')[:-1], urlsafe_base64_encode(force_bytes(user.pk)),
                    urlsafe_base64_encode(force_bytes(email)), TokenGenerator().make_token(user))

                message = render_to_string('email_verification.html', {
                    'name': name,
                    'email_verification_url': email_verification_url
                })
                email = EmailMessage(
                    'Email verification', message, to=[email]
                )
                email.send()
            except Exception:
                pass

        return Response(data=self.get_serializer(user).data)

    def patch(self, request, *args, **kwargs):
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


class UserSingUpView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request, *args, **kwargs):
        serializer = CreateUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'message': 'Some fields are missing',
                'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        try:
            user = User.objects.create(email=data['email'], first_name=data['first_name'], last_name=data['last_name'],
                                       username=data['email'], company=data['company'], user_role=data['role'],
                                       title=data['title'])
            user.set_password(data['password'])
            user.save()
        except IntegrityError as e:
            return Response({
                'message': 'Email already exists.',
                'errors': {'email': 'Email already exists.'}
                 }, status=status.HTTP_400_BAD_REQUEST)

        try:
            name = user.first_name + ' ' + user.last_name
            email_verification_url = '%s/api/user/verify_email?uid=%s&email=%s&token=%s' % (
                request.build_absolute_uri('/')[:-1], urlsafe_base64_encode(force_bytes(user.pk)),
                urlsafe_base64_encode(force_bytes(user.email)), TokenGenerator().make_token(user))

            message = render_to_string('email_verification.html', {
                'name': name,
                'email_verification_url': email_verification_url,
            })
            email = EmailMessage(
                'Email verification', message, to=[user.email]
            )
            email.send()
        except Exception:
            pass

        return Response(data=UserSerializer(user).data, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def get(request):
        uid = force_text(urlsafe_base64_decode(request.query_params['uid']))
        email = force_text(urlsafe_base64_decode(request.query_params['email']))

        user = User.objects.get(pk=uid)
        if user is None or not TokenGenerator().check_token(user, request.query_params['token']):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            user.email = email
            user.username = email
            user.is_email_verified = True
            user.save()
            return redirect('/email_verification')


class ResendEmailView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        email = request.data['email']
        user = User.objects.get(email=email)

        if user:
            name = user.first_name + ' ' + user.last_name
            email_verification_url = '%s/api/user/verify_email?uid=%s&email=%s&token=%s' % (
                request.build_absolute_uri('/')[:-1], urlsafe_base64_encode(force_bytes(user.pk)),
                urlsafe_base64_encode(force_bytes(user.email)), TokenGenerator().make_token(user))

            try:
                message = render_to_string('email_verification.html', {
                    'name': name,
                    'email_verification_url': email_verification_url,
                })
                email = EmailMessage(
                    'Email verification', message, to=[user.email]
                )
                email.send()
            except Exception:
                pass
            return Response(dict(detail="Resend email verification code done successfully."), status=201)
        return Response(dict(detail='The provided email did not match'), status=200)


class ResetPasswordEmailAPIView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request, *args, **kwargs):
        email = request.data['email']
        user = User.objects.get(email=email)
        if user:
            try:
                name = user.first_name + ' ' + user.last_name
                reset_password_url = '%s/login/reset_password?uid=%s&token=%s' % (
                    request.build_absolute_uri('/')[:-1], urlsafe_base64_encode(force_bytes(user.pk)),
                    TokenGenerator().make_token(user))

                message = render_to_string('reset_password.html', {
                    'name': name,
                    'reset_password_url': reset_password_url
                })
                email = EmailMessage(
                    'Please reset your password.', message, to=[user.email],
                )
                email.send()
            except Exception:
                pass
            return Response(dict(detail="Reset password email was sent successfully."), status=201)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


class ResetPasswordAPIView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request, *args, **kwargs):
        uid = force_text(urlsafe_base64_decode(request.data['uid']))
        password = request.data['password']
        user = User.objects.get(pk=uid)

        if user is None or not TokenGenerator().check_token(user, request.data['token']):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        return Response(dict(detail="Password was reset successfully."), status=201)


class ChangePasswordAPIView(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request, *args, **kwargs):
        email = request.data['email']
        new_password = request.data['new_password']
        current_password = request.data['current_password']
        user = User.objects.get(email=email)

        if check_password(current_password, user.password) is True:
            user.set_password(new_password)
            user.save()
            return Response(dict(detail="Password was changed successfully."), status=201)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter


class RequestRoleView(APIView):

    @staticmethod
    def put(request, *args, **kwargs):
        email = request.data['email']
        role = request.data['role']
        description = request.data['description']
        user = User.objects.get(email=email)

        if user:
            user.request_role = role
            user.request_description = description
            user.status = 'review'
            user.save()
            return Response(data=UserSerializer(user).data, status=status.HTTP_201_CREATED)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class UploadAvatar(APIView):
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def put(request, *args, **kwargs):
        email = request.data['email']
        file = request.data['file']
        user = User.objects.get(email=email)

        if user:
            format, imgstr = file.split(';base64,')
            ext = format.split('/')[-1]
            data = ContentFile(base64.b64decode(imgstr))
            if user.avatar:
                original_file = user.avatar.name
                file_path = 'media/' + original_file
                os.remove(file_path)
            file_name = f"{datetime.datetime.now().isoformat().replace(':', '-')}." + ext
            user.avatar.save(file_name, data, save=True)
            return Response(data=UserSerializer(user).data, status=status.HTTP_201_CREATED)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

