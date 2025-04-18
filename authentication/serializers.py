from rest_framework import serializers
from .models import Users, Roles, OTP
from django.contrib.auth.hashers import make_password
from AI_Profile_Generator import utils


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'first_name', 'community_id','last_name', 'email', 'password', 'phone_number', 'address', 'bldg_suite_unit', 'zipcode', 'location', 'state', 'realestate_lic_no', 'state_lic_issued', 'brokerage_number', 'property_management_company_name', 'created_date', 'modified_date', 'community_id', 'role_id', 'image']
        extra_kwargs = {
            'password': {'write_only': True}  # Make password write-only
        }

    def create(self, validated_data):
        # Check if email already exists
        if Users.objects.filter(email=validated_data['email']).exists():
            raise serializers.ValidationError('A user with this email already exists.')

        # Hash the password before saving
        password = validated_data.pop('password')
        user = Users(**validated_data)
        user.password = make_password(password)  # Hash password
        user.is_active = True
        user.save()
        
        #Sent validation email with OTP
        otp_instance, validity_minutes = OTP.generate_otp(user, 'email_verification')
        template_name = "email_verification"
        context_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'otp': otp_instance.otp,
            'validity': validity_minutes,
        }
        utils.send_html_email(to_email=user.email, template_name=template_name, context_data=context_data)
        
        return user

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        profile_image = validated_data.get('image', instance.image)
        
        if profile_image:
            instance.image = validated_data.get('image', instance.image)
        
        instance.save()
        return instance
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ForgotPasswordOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()    

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField()

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Roles
        fields = ['id', 'role_name']
