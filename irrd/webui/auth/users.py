import hashlib
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import date, timedelta
from typing import Optional, Union

import passlib
import wtforms
from imia import (
    AuthenticationMiddleware,
    LoginManager,
    SessionAuthenticator,
    UserLike,
    UserProvider,
)
from sqlalchemy.orm import joinedload
from starlette.middleware import Middleware
from starlette.requests import HTTPConnection
from starlette_wtf import StarletteForm

from irrd.storage.models import AuthUser
from irrd.storage.orm_provider import ORMSessionProvider


class AuthProvider(UserProvider):
    async def find_by_id(self, connection: HTTPConnection, identifier: str) -> Optional[UserLike]:
        session_provider = ORMSessionProvider()
        target = session_provider.session.query(AuthUser).filter_by(email=identifier).options(joinedload("*"))
        user = await session_provider.run(target.one)
        session_provider.session.expunge_all()
        session_provider.commit_close()
        return user

    async def find_by_username(
        self, connection: HTTPConnection, username_or_email: str
    ) -> Optional[UserLike]:
        return await self.find_by_id(connection, username_or_email)

    async def find_by_token(self, connection: HTTPConnection, token: str) -> Optional[UserLike]:
        return None


class PasswordHandler:
    hasher = passlib.hash.bcrypt

    def verify(self, plain: str, hashed: str) -> bool:
        try:
            return self.hasher.verify(plain, hashed)
        except ValueError:
            return False

    def hash(self, plain: str):
        return self.hasher.hash(plain)


secret_key = "key!"
user_provider = AuthProvider()
password_handler = PasswordHandler()
login_manager = LoginManager(user_provider, password_handler, secret_key)


authenticators = [
    SessionAuthenticator(user_provider=user_provider),
]

auth_middleware = Middleware(AuthenticationMiddleware, authenticators=authenticators)


def verify_password(user: AuthUser, plain: str) -> bool:
    return password_handler.verify(plain, user.get_hashed_password())


class CurrentPasswordForm(StarletteForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fields.move_to_end("current_password")
        self._fields.move_to_end("submit")

    current_password = wtforms.PasswordField(
        "Your current password (for verification)",
        validators=[wtforms.validators.DataRequired()],
    )

    async def validate(self, extra_validators=None, current_user: Optional[AuthUser] = None):
        if not await super().validate(extra_validators):
            return False

        if not verify_password(current_user, self.current_password.data):
            # TODO: log
            self.current_password.errors.append("Incorrect password.")
            return False

        return True


PASSWORD_RESET_TOKEN_ROOT = date(2022, 1, 1)
PASSWORD_RESET_SECRET = "aaaaa"
PASSWORD_RESET_VALIDITY_DAYS = 7


class AuthUserToken:
    def __init__(self, user: AuthUser):
        self.user_key = str(user.pk) + str(user.updated) + user.password

    def generate_token(self) -> str:
        expiry_date = date.today() + timedelta(days=PASSWORD_RESET_VALIDITY_DAYS)
        expiry_days = expiry_date - PASSWORD_RESET_TOKEN_ROOT

        hash_str = urlsafe_b64encode(self._hash(expiry_days.days)).decode("ascii")
        return str(expiry_days.days) + "-" + hash_str

    def validate_token(self, token: str) -> bool:
        try:
            expiry_days, input_hash_encoded = token.split("-", 1)
            expiry_date = PASSWORD_RESET_TOKEN_ROOT + timedelta(days=int(expiry_days))

            expected_hash = self._hash(expiry_days)
            input_hash = urlsafe_b64decode(input_hash_encoded)

            return expiry_date >= date.today() and secrets.compare_digest(input_hash, expected_hash)
        except ValueError:
            return False

    def _hash(self, expiry_days: Union[int, str]) -> bytes:
        hash_data = PASSWORD_RESET_SECRET + self.user_key + str(expiry_days)
        return hashlib.sha224(hash_data.encode("utf-8")).digest()
