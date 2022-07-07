import hashlib
import secrets
import textwrap
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import date, timedelta
from typing import Any, Dict, Union

from starlette.requests import Request

from irrd.conf import get_setting
from irrd.storage.models import AuthMntner, AuthUser, RPSLDatabaseObject
from irrd.utils.email import send_email

PASSWORD_RESET_TOKEN_ROOT = date(2022, 1, 1)
PASSWORD_RESET_SECRET = "aaaaa"
PASSWORD_RESET_VALIDITY_DAYS = 7


# From https://github.com/accent-starlette/starlette-core/
def message(request: Request, message: Any, category: str = "success") -> None:
    if category not in ["info", "success", "danger", "warning"]:
        raise ValueError(f"Unknown category: {category}")
    if "_messages" not in request.session:
        request.session["_messages"] = []
    request.session["_messages"].append({"message": message, "category": category})


# From https://github.com/accent-starlette/starlette-core/
def get_messages(request: Request):
    return request.session.pop("_messages") if "_messages" in request.session else []


def send_template_email(
    recipient: str, template_key: str, request: Request, template_kwargs: Dict[str, Any]
) -> None:
    from . import templates

    subject = templates.get_template(f"{template_key}_mail_subject.txt").render(
        request=request, **template_kwargs
    )
    body = templates.get_template(f"{template_key}_mail.txt").render(request=request, **template_kwargs)
    send_email(recipient, subject, body)


async def notify_mntner(session_provider, user: AuthUser, mntner: AuthMntner, explanation: str):
    query = session_provider.session.query(RPSLDatabaseObject).outerjoin(AuthMntner)
    query = query.filter(
        RPSLDatabaseObject.pk == str(mntner.rpsl_mntner_obj_id),
    )
    rpsl_mntner = await session_provider.run(query.one)
    recipients = rpsl_mntner.parsed_data.get("mnt-nfy", []) + rpsl_mntner.parsed_data.get("notify", [])

    subject = f"Notification of {mntner.rpsl_mntner_source} database changes"
    body = get_setting("email.notification_header", "").format(sources_str=mntner.rpsl_mntner_source)
    body += textwrap.dedent(
        f"""
        This message is auto-generated.
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        Internal authentication was changed for
        mntner {mntner.rpsl_mntner_pk} in source {mntner.rpsl_mntner_source}
        by user {user.name} ({user.email}).
    """
    )
    body += f"\n{explanation.strip()}\n"
    body += textwrap.dedent(
        """
        Note that this change is not visible in the RPSL object,
        as these authentication settings are stored internally in IRRD.
    """
    )
    for recipient in recipients:
        send_email(recipient, subject, body)


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
