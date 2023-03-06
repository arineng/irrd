import functools
from typing import Any, Dict, Optional

import limits
from starlette.requests import Request
from starlette.responses import Response

from irrd.storage.models import AuthUser, RPSLDatabaseObject
from irrd.storage.orm_provider import ORMSessionProvider
from irrd.utils.email import send_email
from irrd.utils.text import remove_auth_hashes
from irrd.webui import RATE_LIMIT_POST_200_NAMESPACE, templates

FAILED_AUTH_RATE_LIMIT = limits.parse("30/hour")


def session_provider_manager(func):
    @functools.wraps(func)
    async def endpoint_wrapper(*args, **kwargs):
        provider = ORMSessionProvider()
        response = await func(*args, session_provider=provider, **kwargs)
        provider.commit_close()
        return response

    return endpoint_wrapper


def session_provider_manager_sync(func):
    @functools.wraps(func)
    def endpoint_wrapper(*args, **kwargs):
        provider = ORMSessionProvider()
        response = func(*args, session_provider=provider, **kwargs)
        provider.commit_close()
        return response

    return endpoint_wrapper


def rate_limit_post_200(func):
    @functools.wraps(func)
    async def endpoint_wrapper(*args, **kwargs):
        request = next((arg for arg in list(args) + list(kwargs.values()) if isinstance(arg, Request)), None)

        limiter = request.app.state.rate_limiter
        permitted = await limiter.test(
            FAILED_AUTH_RATE_LIMIT, RATE_LIMIT_POST_200_NAMESPACE, request.client.host
        )
        if request and request.method == "POST" and not permitted:
            return Response("Request denied due to rate limiting", status_code=403)

        response = await func(*args, **kwargs)
        if request and request.method == "POST" and response.status_code == 200:
            await limiter.hit(FAILED_AUTH_RATE_LIMIT, RATE_LIMIT_POST_200_NAMESPACE, request.client.host)

        return response

    return endpoint_wrapper


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
    subject = templates.get_template(f"{template_key}_mail_subject.txt").render(
        request=request, **template_kwargs
    )
    body = templates.get_template(f"{template_key}_mail.txt").render(request=request, **template_kwargs)
    send_email(recipient, subject, body)


def filter_auth_hash_non_mntner(user: Optional[AuthUser], rpsl_object: RPSLDatabaseObject) -> str:
    if user:
        user_mntners = [
            (mntner.rpsl_mntner_pk, mntner.rpsl_mntner_source) for mntner in user.mntners_user_management
        ]

        if rpsl_object.object_class != "mntner" or (rpsl_object.rpsl_pk, rpsl_object.source) in user_mntners:
            rpsl_object.hashes_hidden = False
            return rpsl_object.object_text

    rpsl_object.hashes_hidden = True
    return remove_auth_hashes(rpsl_object.object_text)
