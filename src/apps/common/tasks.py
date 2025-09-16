from django.core.mail import EmailMessage
from celery import shared_task
from django.conf import settings

@shared_task
def send_user_mail(subject,recipients,message):
    mail = EmailMessage(
        subject=subject,
        body=message,
        from_email=settings.EMAIL_HOST_USER,
        to=recipients
    )
    mail.send()