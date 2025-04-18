from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from ..serializers import (
    UserSerializer,
    LoginSerializer,
    ForgotPasswordOtpSerializer,
    ResetPasswordSerializer,
    RoleSerializer,
)
from ..models import *
from rest_framework.permissions import AllowAny, IsAuthenticated
import random
from django.core.mail import send_mail
from AI_Profile_Generator import constants, settings, utils
from django.contrib.auth.hashers import check_password
from datetime import datetime, timedelta
from django.contrib.auth.hashers import make_password
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema


logger = logging.getLogger(__name__)


class RegisterUser(APIView):
    """
    API View for user registration.

    This endpoint allows users to register by providing necessary details.
    On successful registration, the user details are returned along with a success message.
    Validation errors or unexpected exceptions are also handled, and appropriate error responses are returned.

    Methods:
        post: Handles POST requests for user registration.
    """
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        try:
            print(request.data)
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                otp = OTP.objects.filter(user=user.id).first()
                data = {
                    "id": user.id,
                    "email": user.email,
                    "image_url": user.image.url if user.image else None,
                    "otp":otp.otp
                }

                return utils.success_response(
                    message=constants.MESSAGES["OTP_SEND"],
                    data=data,
                    status_code=status.HTTP_200_OK,
                    api_status_code=status.HTTP_200_OK,
                )

            return utils.error_response(
                message=constants.MESSAGES["VALIDATION_FAILED"],
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["USER_REGISTRATION_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )

from authentication.models import *
class LoginUser(APIView):
    def post(self, request):
        """
        Handle POST request for user login.

        Args:
            request (Request): The HTTP request object containing login credentials.

        Returns:
            Response: A JSON response with a success or error message and user details if applicable.
        """
        try:
            print(request.data.get('email'), request.data.get('password'))
            user = authenticate(request, email=request.data.get('email'),password=request.data.get('password'))
            if user: 
                user_role = user.get_role
                # Restrict Super Admin login
                if user.status=='deactivated':
                    return utils.error_response(
                        message="Inactive account.",
                        errors=None,
                        status_code=status.HTTP_200_OK,
                        api_status_code=status.HTTP_200_OK,
                    )
                if user_role == "Super Admin":
                    return utils.error_response(
                        message=constants.MESSAGES["SUPER_ADMIN_LOGIN_DENIED"],
                        errors=None,
                        status_code=status.HTTP_200_OK,
                        api_status_code=status.HTTP_200_OK,
                    )

                first_name = user.first_name
                last_name = user.last_name
                

                refresh = RefreshToken.for_user(user)
                data = {
                    "user_id": user.id,
                    "user_type": user_role,
                    "first_name": first_name,
                    "last_name": last_name,
                    "token": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                }
                return utils.success_response(
                    message=constants.MESSAGES["LOGIN_SUCCESS"],
                    data=data,
                    status_code=status.HTTP_200_OK,
                    api_status_code=status.HTTP_200_OK,
                )

            return utils.error_response(
                message=constants.MESSAGES["INVALID_CREDENTIALS"],
                errors=None,
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return utils.error_response(
                message=constants.MESSAGES["ERROR_GENERAL"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )

class SuperUserLogin(APIView):
    """
    API View for Super Admin login.

    Methods:
        post: Handles POST requests for Super Admin authentication.
    """

    def post(self, request):
        """
        Handle POST request for Super Admin login.

        Args:
            request (Request): The HTTP request object containing login credentials.

        Returns:
            Response: A JSON response with a success or error message and user details if applicable.
        """
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                password = serializer.validated_data["password"]

                try:
                    # Fetch the user based on the email
                    user = Users.objects.get(email=email)
                    user_role = user.get_role

                    if user_role == "Super Admin":
                        first_name = user.first_name
                        last_name = user.last_name
                        role_name = user.role_id.role_name

                        # Verify the password using Django's check_password method
                        if check_password(password, user.password):
                            refresh = RefreshToken.for_user(user)
                            data = {
                                "user_id": user.id,
                                "user_type": role_name,
                                "first_name": first_name,
                                "last_name": last_name,
                                "token": {
                                    "refresh": str(refresh),
                                    "access": str(refresh.access_token),
                                },
                            }
                            return utils.success_response(
                                message=constants.MESSAGES["SUPER_ADMIN_LOGIN_SUCCESS"],
                                data=data,
                                status_code=status.HTTP_200_OK,
                                api_status_code=status.HTTP_200_OK,
                            )
                        return utils.error_response(
                            message=constants.MESSAGES["INVALID_CREDENTIALS"],
                            errors=None,
                            status_code=status.HTTP_400_BAD_REQUEST,
                            api_status_code=status.HTTP_200_OK,
                        )

                    return utils.error_response(
                        message=constants.MESSAGES["ONLY_SUPER_ADMIN_ALLOWED"],
                        errors=None,
                        status_code=status.HTTP_400_BAD_REQUEST,
                        api_status_code=status.HTTP_200_OK,
                    )

                except Users.DoesNotExist:
                    return utils.error_response(
                        message=constants.MESSAGES["INVALID_CREDENTIALS"],
                        errors=None,
                        status_code=status.HTTP_400_BAD_REQUEST,
                        api_status_code=status.HTTP_200_OK,
                    )

            return utils.error_response(
                message=constants.MESSAGES["VALIDATION_FAILED"],
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return utils.error_response(
                message=constants.MESSAGES["ERROR_GENERAL"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


class ForgotPasswordView(APIView):
    """
    API View for initiating the password reset process by sending an OTP to the user's email.

    Methods:
        post: Handles POST requests to send OTP for password reset.
    """

    permission_classes = [AllowAny]

    def post(self, request):
            """
            Handle POST request for sending OTP for password reset.

            Args:
                request (Request): The HTTP request object containing the email.

            Returns:
                Response: A JSON response with the OTP sent message or error.
            """
        # try:
            
            email = request.data.get("email")
          
            user = Users.objects.get(email=email)

            # Generate a 4-digit OTP and save it
            otp_instance, validity_minutes = OTP.generate_otp(user, 'forget_password')
            template_name = "forget_password"
            context_data = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'otp': otp_instance.otp,
                'validity': validity_minutes,
            }

            utils.send_html_email(to_email=user.email, template_name=template_name, context_data=context_data)
        
            return utils.success_response(
                message=constants.MESSAGES["OTP_SENT_SUCCESS"],
                data={
                "user_id": user.id,
                "email" : user.email
                },
                status_code=status.HTTP_200_OK,
                api_status_code=status.HTTP_200_OK,
            )

        # except Users.DoesNotExist:
        #     return utils.error_response(
        #         message=constants.MESSAGES["USER_NOT_FOUND"],
        #         errors=None,
        #         status_code=status.HTTP_404_NOT_FOUND,
        #         api_status_code=status.HTTP_404_NOT_FOUND,
        #     )
            
        # except Exception as e:
        #     # Handle unexpected exceptions
        #     return utils.error_response(
        #         message=constants.MESSAGES["PROCESSING_REQUEST_ERROR"],
        #         errors=str(e),
        #         status_code=status.HTTP_400_BAD_REQUEST,
        #         api_status_code=status.HTTP_400_BAD_REQUEST,
        #     )


class ForgotPasswordOtpView(APIView):
    """
    API View for verifying OTP during the password reset process.

    Methods:
        post: Handles POST requests to verify the OTP.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=ForgotPasswordOtpSerializer)
    def post(self, request):
        """
        Handle POST request for verifying OTP for password reset.

        Args:
            request (Request): The HTTP request object containing email and OTP.

        Returns:
            Response: A JSON response indicating the result of OTP verification.
        """
        serializer = ForgotPasswordOtpSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            otp = serializer.validated_data["otp"]

            try:
                # Retrieve the user based on the provided email
                user = Users.objects.get(email=email)

                # Retrieve OTP associated with the user
                otp_instance = OTP.objects.filter(
                    user=user, otp=otp, otp_type="forget_password", is_expired=False
                ).first()

                if otp_instance:
                    # Check if the OTP has expired
                    if otp_instance.expires_at < now():
                        otp_instance.is_expired = True
                        otp_instance.save()
                        return utils.error_response(
                            message=constants.MESSAGES["OTP_EXPIRED"],
                            errors={"email": email, "otp": otp},
                            status_code=status.HTTP_400_BAD_REQUEST,
                            api_status_code=status.HTTP_400_BAD_REQUEST,
                        )

                    # OTP is valid
                    return utils.success_response(
                        message=constants.MESSAGES["OTP_VERIFIED_SUCCESS"],
                        data={"email": email},
                        status_code=status.HTTP_200_OK,
                        api_status_code=status.HTTP_200_OK,
                    )
                else:
                    # OTP is invalid
                    return utils.error_response(
                        message=constants.MESSAGES["INVALID_OTP"],
                        errors={"email": email, "otp": otp},
                        status_code=status.HTTP_400_BAD_REQUEST,
                        api_status_code=status.HTTP_400_BAD_REQUEST,
                    )

            except Users.DoesNotExist:
                return utils.error_response(
                    message=constants.MESSAGES["USER_NOT_FOUND"],
                    errors={"email": email},
                    status_code=status.HTTP_404_NOT_FOUND,
                    api_status_code=status.HTTP_404_NOT_FOUND,
                )

        # Validation errors
        return utils.error_response(
            message=constants.MESSAGES["VALIDATION_FAILED"],
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST,
            api_status_code=status.HTTP_400_BAD_REQUEST,
        )
    
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle POST request to reset a user's password.

        Args:
            request (Request): The HTTP request object containing email and new password.

        Returns:
            Response: A JSON response indicating the result of the password reset.
        """
        try:
            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                
                new_password = serializer.validated_data["new_password"]

                try:
                    user = Users.objects.get(email=email)
                    user.set_password(new_password) 
                    user.save()

                    return utils.success_response(
                        message=constants.MESSAGES["PASSWORD_RESET_SUCCESS"],
                        data={"email": email},
                        status_code=status.HTTP_200_OK,
                        api_status_code=status.HTTP_200_OK,
                    )

                except Users.DoesNotExist:
                    return utils.error_response(
                        message=constants.MESSAGES["USER_NOT_FOUND"],
                        errors={"email": email},
                        status_code=status.HTTP_404_NOT_FOUND,
                        api_status_code=status.HTTP_404_NOT_FOUND,
                    )

            # Validation errors
            return utils.error_response(
                message=constants.MESSAGES["PROCESSING_REQUEST_ERROR"],
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_200_OK,
            )

        except Exception as e:
            # Handle unexpected exceptions
            return utils.error_response(
                message=constants.MESSAGES["PROCESSING_REQUEST_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


class RolesListView(APIView):
    """
    API View for retrieving roles for non-super admin users.

    Methods:
        get: Fetches a list of roles excluding super admin.
    """

    def get(self, request):
        """
        Handle GET request to fetch the roles.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A JSON response containing the roles or error message.
        """
        try:
            roles = Roles.objects.filter()
            serializer = RoleSerializer(roles, many=True)

            if roles.exists():
                return utils.success_response(
                    message=constants.MESSAGES["ROLES_RETRIEVED_SUCCESS"],
                    data=serializer.data,
                    status_code=status.HTTP_200_OK,
                    api_status_code=status.HTTP_200_OK,
                )
            else:
                return utils.error_response(
                    message=constants.MESSAGES["NO_ROLES_FOUND"],
                    errors={},
                    status_code=status.HTTP_404_NOT_FOUND,
                    api_status_code=status.HTTP_404_NOT_FOUND,
                )

        except Exception as e:
            # Handle unexpected exceptions
            return utils.error_response(
                message=constants.MESSAGES["ROLES_RETRIEVAL_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


class VerifyEmailOtpView(APIView):
    """
    API View for verifying email OTP.
    """

    def post(self, request):
        """
        Handle POST request to send an OTP for email verification.

        Args:
            request (Request): The HTTP request object containing the email.

        Returns:
            Response: A JSON response with the OTP and email information.
        """
        try:
            email = request.data.get("email")

            if not email:
                return utils.error_response(
                    message="Email is required",
                    errors={"email": "Email field is empty."},
                    status_code=status.HTTP_400_BAD_REQUEST,
                    api_status_code=status.HTTP_400_BAD_REQUEST,
                )

            otp = random.randint(1000, 9999)
            send_mail(
                subject="Verify Email OTP",
                message=f"Your OTP for email verification is: {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )

            data = {"email": email, "otp": otp}
            return utils.success_response(
                message=constants.MESSAGES["OTP_SENT_SUCCESS"],
                data=data,
                status_code=status.HTTP_200_OK,
                api_status_code=status.HTTP_200_OK,
            )

        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["OTP_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


class UserView(APIView):
    """
    API View for fetching user profile by user ID.
    """
    
    # permission_classes = [IsAuthenticated] 

    def get(self, request, *args, **kwargs):


        """
        Handle GET request to fetch user profile details.

        Args:
            request (Request): The HTTP request object.
            kwargs (dict): Contains the user ID.

        Returns:
            Response: A JSON response containing the user profile or error message.
        """
        user_id = kwargs.get("id")

        try:
            # Fetch user details by user ID
            user_details = Users.objects.get(id=user_id)
            serializer = UserSerializer(user_details)

            return utils.success_response(
                message=constants.MESSAGES["USER_PROFILE_FETCH_SUCCESS"],
                data=serializer.data,
                status_code=status.HTTP_200_OK,
                api_status_code=status.HTTP_200_OK,
            )

        except Users.DoesNotExist:
            return utils.error_response(
                message=constants.MESSAGES["USER_NOT_FOUND"],
                errors=None,
                status_code=status.HTTP_404_NOT_FOUND,
                api_status_code=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["USER_PROFILE_FETCH_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


    def put(self, request, *args, **kwargs):
        """
        Handle PUT request to update a user's information.

        Args:
            request (Request): The HTTP request object containing user update data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments, such as the user ID.

        """
        try:
            user_id = self.kwargs.get("id")
            user = Users.objects.get(id=user_id)
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return utils.success_response(
                    message=constants.MESSAGES["USER_UPDATE_SUCCESS"],
                    data=serializer.data,
                    status_code=status.HTTP_200_OK,
                    api_status_code=status.HTTP_200_OK,
                )

        except Users.DoesNotExist:
            return utils.error_response(
                message=constants.MESSAGES["USER_NOT_FOUND"],
                errors=None,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["USER_UPDATE_ERROR"],
                errors=str(e),
                status=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )


class VerifyOTPAPIView(APIView):
    def post(self, request):
        otp = request.data.get("otp")
        otp_type = request.data.get("otp_type")
        user_id = request.data.get('user_id')
        
        
        if not otp or not otp_type:
            return utils.error_response(
                message=constants.MESSAGES["OTP_REQUIRED"],
                errors="OTP or otp_type field is empty.",
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = Users.objects.get(id=user_id)
            otp_instance = OTP.objects.get(user=user, otp=otp, otp_type=otp_type, is_expired=False)
            if otp_instance.expires_at > now():
                otp_instance.is_expired = True
                otp_instance.save()
                
                if otp_type == 'email_verification':
                    user.is_email_verified = True
                    user.is_active = True
                    
                    
                    utils.send_mail_to_user(
                        subject="Email Verification",
                        message=f"Your email has been verified. Welcome to our platform!",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],)
                    
                elif otp_type == 'mobile_verification':
                    user.is_phone_verified = True
                
                user.save()
                data = {
                    "id": user.id,
                    "email": user.email,
                    "image_url": user.image.url if user.image else None,
                }
                return utils.success_response(
                    message=constants.MESSAGES["OTP_VERIFIED_SUCCESS"],
                    data=data,
                    status_code=status.HTTP_200_OK)
            else:
                return utils.error_response(
                    message=constants.MESSAGES["OTP_EXPIRED"],
                    errors=None,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    api_status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["OTP_VERIFICATION_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    """Resends an OTP to a user.

    Marks the existing OTP as expired and sends a new OTP to the user's email.
    """
    def post(self, request):
        """Handles the POST request for resending OTPs.

        Args:
            self: Instance of the class.
            request (HttpRequest): The incoming request object.

        Returns:
            Response: A success or error response depending on the outcome.

        Raises:
            Exception: If there's an error during processing, like user not found or OTP issues.
        """
        try:
            user_id = request.data.get('user_id')
            otp_type = request.data.get('otp_type')

            if not user_id or not otp_type:
                return utils.error_response(
                    message=constants.MESSAGES["EMAIL_OTP_REQUIRED"],
                    errors="Email or otp_type field is empty.",
                    status_code=status.HTTP_400_BAD_REQUEST,
                    api_status_code=status.HTTP_400_BAD_REQUEST,
                )

            user = Users.objects.get(id=user_id)
            otp_instance = OTP.objects.get(user=user, otp_type=otp_type, is_expired=False)

            otp_instance.is_expired = True
            otp_instance.save()

            otp_instance, validity_minutes = OTP.generate_otp(user, 'email_verification')
            template_name = "email_verification"
            context_data = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'otp': otp_instance.otp,
                'validity': validity_minutes,
            }
        
            utils.send_html_email(to_email = user.email,template_name=template_name,  context_data=context_data)
            return utils.success_response(
                message=constants.MESSAGES["OTP_RESENT_SUCCESS"],
                data=None,
                status_code=status.HTTP_200_OK)
        except Exception as e:
            return utils.error_response(
                message=constants.MESSAGES["OTP_RESEND_ERROR"],
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
                api_status_code=status.HTTP_400_BAD_REQUEST)

