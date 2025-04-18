from datetime import datetime
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.utils.timezone import now, timedelta

class BaseModel(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        abstract = True

class Roles(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role_name = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.role_name

class EmailTemplate(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)  # Unique identifier for the template
    subject = models.CharField(max_length=200)
    html_body = models.TextField()

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)
    
class Users(AbstractUser, BaseModel):
    username = None 
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",  # Avoid conflict
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_set",  # Avoid conflict
        blank=True,
    )
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('deactivated', 'Deactivated'),
    ]

    role_id = models.ForeignKey(Roles, on_delete=models.CASCADE, null=True)
    first_name = models.CharField(max_length=255, null=True, blank=True) 
    last_name = models.CharField(max_length=255, null=True, blank=True)  
    email = models.EmailField(max_length=255, null=True, blank=True, unique=True)
    password = models.CharField(max_length=255, null=True, blank=True) 
    phone_number = models.CharField(max_length=255, null=True, blank=True) 
    address = models.TextField(null=True, blank=True) 
    bldg_suite_unit = models.TextField(null=True, blank=True) 
    zipcode = models.CharField(max_length=255, null=True, blank=True) 
    location = models.CharField(max_length=255, null=True, blank=True) 
    state = models.CharField(max_length=255, null=True, blank=True)
    realestate_lic_no = models.CharField(max_length=255, null=True, blank=True)  
    state_lic_issued = models.CharField(max_length=255, null=True, blank=True) 
    brokerage_number = models.CharField(max_length=255, null=True, blank=True) 
    property_management_company_name = models.CharField(max_length=255, null=True, blank=True) 
    image = models.ImageField(upload_to='ai_images/', null=True, blank=True)
    position = models.CharField(max_length=20, null=True)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default='active')
    is_deleted = models.BooleanField(default=False)
    
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    
    objects = CustomUserManager()
    REQUIRED_FIELDS = [ 'password',]
    USERNAME_FIELD = 'email'
    
    def __str__(self):
        return self.email
    
    @property
    def get_role(self):
        return self.role_id.role_name if self.role_id else None

class OTP(models.Model):
    OTP_TYPE_CHOICES = [
        ('email_verification', 'Email Verification'),
        ('mobile_verification', 'Mobile Verification'),
        ('forget_password', 'Forget Password'),
    ]

    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPE_CHOICES)
    is_expired = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    
    @staticmethod
    def generate_otp(user, otp_type, validity_minutes=10):
        import random
        otp = f"{random.randint(1000, 9999)}"
        expiration_time = now() + timedelta(minutes=validity_minutes)
        otp_instance = OTP.objects.create(
            user=user,
            otp=otp,
            otp_type=otp_type,
            expires_at=expiration_time
        )
        return otp_instance, validity_minutes
    
class Modules(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_name = models.CharField(max_length=255, null=True, blank=True)
    def __str__(self):
        return self.module_name


class ModuleRolePermissions(BaseModel):
    module_id = models.ForeignKey(Modules, on_delete=models.CASCADE,null=True)
    role_id = models.ForeignKey(Roles, on_delete=models.CASCADE,null=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    can_add = models.BooleanField(null=True)
    can_edit = models.BooleanField(null=True)
    can_view = models.BooleanField(null=True)