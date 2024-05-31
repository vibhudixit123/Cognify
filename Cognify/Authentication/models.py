from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from rest_framework_simplejwt.tokens import RefreshToken

class CustomUserManager(BaseUserManager):

    def create_user(self,email,password=None):
        if not email:
            raise ValueError("user must have email address")
        if not password:
            raise ValueError("user must have password")
        
        normalized_email = self.normalize_email(email)
        user = self.model(email=normalized_email)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_SuperUser(self,email,password=None):
        user = self.create_user(email=email,password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user
    
## Model Creation

class CustomUser(AbstractBaseUser):
    email = models.EmailField(verbose_name='email_address',max_length=255,unique=True)

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email}"

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin
    
    @property
    def is_active(self):
        return self.is_active

    @property
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        refresh['email'] = self.email
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

class EmailOTP(models.Model):
    email_address = models.EmailField(
        verbose_name='Email Address',
        max_length=255,
        unique=True,
    )
    otp = models.IntegerField(null=True, blank=True)
    otp_created_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.email_address}"
    
    class Meta:
         verbose_name_plural = 'Email OTPs'