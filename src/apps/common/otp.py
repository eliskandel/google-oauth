from src.apps.auth.models import User
from django.utils.crypto import get_random_string
from django.utils import timezone
from src.apps.common.tasks import send_user_mail
from django.conf import settings

class OTPAction:
    LOGIN = "Login"
    RESET = "Reset"


class OTPhandlers:

    def __init__(
        self,
        request,
        user: User,
        action=OTPAction.LOGIN,
        valid_period=settings.OTP_VALID_PERIOD,
    ):
        self.request = request
        self.user = user
        self.action = action
        self.valid_period = valid_period

    def generate_otp(self):
        otp = get_random_string(length=6, allowed_chars="0123456789")
        self.user.otp = otp
        self.user.otp_created_at = timezone.now()
        self.user.save()
        return otp

    def verify_otp(self, otp):
        if self.user.otp != otp:
            self.user.otp_tries += 1
            self.user.save()
            if self.user.otp_tries >= 3:
                return False, "OTP Tried too many times"

            return False, "Invalid OTP"

        if (
            self.user.otp_created_at
            and self.user.otp_created_at + timezone.timedelta(minutes=self.valid_period)
            < timezone.now()
        ):
            return False, "OTP expired"

        self.user.otp = None
        self.user.otp_tries = 0
        self.user.otp_created_at = None
        self.user.email_verified = True
        self.user.save()
        return True, "OTP Verified"

    def send_otp(self):
        otp = self.generate_otp()
        subject = f"{self.action} OTP"
        receiver = self.user.email
        # if self.action == OTPAction.LOGIN:
        message = f"Hi {self.user.first_name} {self.user.last_name},\n\nYour {self.action} OTP is: {otp}"
        # else:
        #     random_password = get_random_string(length=8,allowed_chars='123456789asdfghjklqwertyuiopzxcvbnm')
        #     message = f'Hi {self.user.first_name} {self.user.last_name},\n\nYour {self.action} password OTP is: {otp}\n\nPlease use this OTP to reset your password\nYour new password is : {random_password}'

        #     self.user.set_password(random_password)
        #     self.user.save()

        send_user_mail.delay(subject, [receiver], message)