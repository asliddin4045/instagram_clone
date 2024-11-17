from shared.utility import email_regex
from shared.utility import phone_regex
from .models import User, UserConfirmation, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from django.core.validators import FileExtensionValidator
from rest_framework import exceptions, serializers
from django.db.models import Q
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from shared.utility import check_email_or_phone, send_phone_code, send_email, check_user_type
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import update_last_login
from rest_framework .generics import get_object_or_404




class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ('id', 'auth_type', 'auth_status')

        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)

        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)

            send_mail(
                subject='Verification Code',
                message=render_to_string('email/authentication/activate_account.html', {'code': code}),
                from_email='alibekhujayev9876@gmail.com',
                recipient_list=[user.email],
                fail_silently=False,
            )

        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_phone_code(user.phone_number, code)

        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)

        if input_type == 'email':
            data = {"email": user_input, "auth_type": VIA_EMAIL}
        elif input_type == 'phone':
            data = {"phone_number": user_input, "auth_type": VIA_PHONE}
        else:
            raise ValidationError({"success": False, "message": "Email yoki telefon raqam kiriting"})

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            raise ValidationError({"success": False, "message": "Bu email allaqachon ishlatilgan"})
        elif value and User.objects.filter(phone_number=value).exists():
            raise ValidationError({"success": False, "message": "Bu telfon raqam allaqachon ishlatilgan"})
        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)


    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password !=confirm_password:
            raise ValidationError(
                {
                    "message": "Parolingiz va tasdiqlash kodingiz bir biriga teng emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message": "Foydalanuvchi nomi 5-30 ta belgidan iborat bo'lishi kerak"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message": "Foydalanuvchi nomi raqam bo'lishi kerak"
                }
            )
        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password(validated_data.get('password', instance.password))
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        'jpeg', 'jpg', 'png', 'heic', 'heif'
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        return instance


class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields[ 'userinput' ] = serializers.CharField(required=True)
        self.fields[ 'username' ] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('userinput')
        user_type = check_user_type(user_input)

        if user_type == 'username':
            username = user_input
        elif user_type == 'email':
            user = self.get_user(email__iexact=user_input)
            username = user.username
        elif user_type == 'phone':
            user = self.get_user(phone_number=user_input)
            username = user.username
        else:
            data = {
                'success': False,
                "message": "Siz email, username yoki telefon raqamni kiritishingiz kerak"
            }
            raise ValidationError(data)

        authentication_kwargs = {
            'username': username,
            'password': data[ 'password' ]
        }

        current_user = User.objects.filter(username__iexact=username).first()
        if current_user is not None and current_user.auth_status not in [ DONE, PHOTO_DONE ]:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Siz ro'yxatdan to'liq utmagansiz"
                }
            )

        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Parol yoki username noto'g'ri"
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [ DONE, PHOTO_DONE ]:
            raise PermissionDenied("Siz Login qila olmaysiz, Ruxsatingiz yo'q")
        data = self.user.token()
        data[ 'auth_status' ] = self.user.auth_status
        data[ 'full_name' ] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    "message": "No account found"
                }
            )
        return users.first()

class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()



class ForgotPasswordSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        email_or_phone = attrs.get('email_or_phone', None)
        if email_or_phone is None:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Email yoki telefon raqam kiritilishi Shart!"
                }
            )
        user = User.objects.filter(Q(phone_number=email_or_phone)|Q(email=email_or_phone))
        if not user.exists():
            raise NotFound(detail="User not found")

        attrs['user'] = user.first()
        return attrs



class ResetPasswordSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password',
        )

    def validate(self, attrs):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)

        if password != confirm_password:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Parollar bir biriga mos kelmadi"
                }
            )
        if password:
            validate_password(password)
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)

