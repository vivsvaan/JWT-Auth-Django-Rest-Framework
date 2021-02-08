import jwt
from django.contrib.auth.models import User
from jwt import InvalidSignatureError, ExpiredSignatureError
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from jwt_auth.permissioning.consts import JWT_SECRET
from jwt_auth.permissioning.utils import get_auth_token


class JWTAuthentication(TokenAuthentication):

    def get_user(self, data):
        return User.objects.get(username=data['username'])

    def authenticate(self, request):
        token = get_auth_token(request)
        if not token:
            return None
        token = token.split(' ')[1]  # token is "TOKEN token_string"
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            return self.get_user(decoded), decoded
        except (ExpiredSignatureError, InvalidSignatureError):
            raise exceptions.AuthenticationFailed("Logged Out")
        except Exception as e:
            print("Exception Occurred", e)
            raise exceptions.AuthenticationFailed("Invalid Token")


auth_permissions = (IsAuthenticated, )
no_permissions = ()
