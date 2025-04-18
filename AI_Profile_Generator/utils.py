from rest_framework import status
from rest_framework.response import Response
from AI_Profile_Generator import settings
from django.core.mail import send_mail
from authentication.models import OTP,EmailTemplate
from django.template import Template, Context
from django.core.mail import EmailMultiAlternatives


def success_response(message, data=None, status_code=status.HTTP_200_OK, api_status_code=status.HTTP_200_OK):
    """
    A utility function to generate success API responses.

    Args:
    - message (str): A message to send with the response.
    - data (dict, optional): The data to include in the response. Defaults to None.
    - status_code (int, optional): The HTTP status code for the response. Defaults to HTTP_200_OK.

    Returns:
    - Response: A DRF Response object with the provided message, data, and status code.
    """
    response_data = {
        "message": message,
        "data": data if data else {},
        "status": status_code,
    }

    return Response(response_data, status=api_status_code, )


def error_response(message, errors=None, status_code=status.HTTP_400_BAD_REQUEST, api_status_code=status.HTTP_400_BAD_REQUEST):
    """
    A utility function to generate error API responses.

    Args:
    - message (str): A message to send with the response.
    - errors (dict, optional): The error details to include in the response. Defaults to None.
    - status_code (int, optional): The HTTP status code for the response. Defaults to HTTP_400_BAD_REQUEST.

    Returns:
    - Response: A DRF Response object with the provided message, error details, and status code.
    """
    response_data = {
        "message": message,
        "errors": errors if errors else {},
        "status": status_code,
    }

    return Response(response_data, status=api_status_code)

def send_mail_to_user(subject=None, message=None, recipient_list=None):
    send_mail(
                        subject=subject,
                        message= message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=recipient_list,
                    )
    
    
def get_email_html(template_name, context_data):
    try:
        template = EmailTemplate.objects.get(name=template_name)
        subject = Template(template.subject).render(Context(context_data))
        html_body = Template(template.html_body).render(Context(context_data))
        return subject, html_body
    except EmailTemplate.DoesNotExist as e:
        raise ValueError(f"Template '{template_name}' not found.") from e
    

def send_html_email(to_email, template_name, context_data):
    try:
        print(to_email,template_name,context_data)
        subject, html_body = get_email_html(template_name, context_data)
        email = EmailMultiAlternatives(
            subject=subject,
            body=html_body,  # Provide HTML content directly
            from_email='from@example.com',
            to=[to_email],
        )
        email.attach_alternative(html_body, "text/html")
        email.send()
    except ValueError as e:
        print(e)