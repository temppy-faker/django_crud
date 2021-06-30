from django.db import models
from django.contrib.auth.models import AbstractUser
from .managers import UserManager
from imagekit.models import ProcessedImageField


class User(AbstractUser):
    email = models.EmailField(verbose_name='email address', max_length=255, unique=True,)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    company = models.CharField(max_length=255)
    user_role = models.CharField(max_length=10, blank=True)
    title = models.CharField(max_length=255)
    request_role = models.CharField(max_length=10, blank=True)
    request_description = models.TextField()
    status = models.CharField(max_length=10, blank=True)
    avatar = models.ImageField(upload_to='avatar', blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email & Password are required by default.

    class Meta:
        db_table = 'users'


class Company(models.Model):
    name = models.CharField(max_length=255, blank=True)
    type = models.CharField(max_length=50, blank=True)
    instagram_link = models.URLField()
    facebook_link = models.URLField()
    linkedin_link = models.URLField()
    twitter_link = models.URLField()
    youtube_link = models.URLField()
    street = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=100, blank=True)
    phone_num = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50, blank=True)
    timezone = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    published = models.BooleanField(default=False)
    created_by = models.CharField(max_length=10, blank=True)
    updated_by = models.CharField(max_length=10, blank=True)

    class Meta:
        db_table = 'company'
