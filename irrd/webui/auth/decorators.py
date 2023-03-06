import functools
from urllib.parse import quote_plus

from starlette.requests import Request
from starlette.responses import RedirectResponse

from irrd.webui import MFA_COMPLETE_SESSION_KEY


def authentication_required(_func=None, mfa_check=True):
    def decorator_wrapper(func):
        @functools.wraps(func)
        async def endpoint_wrapper(*args, **kwargs):
            request = next(
                (arg for arg in list(args) + list(kwargs.values()) if isinstance(arg, Request)), None
            )
            next_redir = request.scope.get("raw_path", "")
            if next_redir:
                next_redir = quote_plus(next_redir, safe="/")

            if not request.auth.is_authenticated:
                redir_url = request.url_for("ui:auth:login") + "?next=" + next_redir
                return RedirectResponse(redir_url, status_code=302)

            if mfa_check and not request.session.get(MFA_COMPLETE_SESSION_KEY):
                redir_url = request.url_for("ui:auth:mfa_authenticate") + "?next=" + next_redir
                return RedirectResponse(redir_url, status_code=302)

            return await func(*args, **kwargs)

        return endpoint_wrapper

    if _func is None:
        return decorator_wrapper
    else:
        return decorator_wrapper(_func)


def mark_user_mfa_incomplete(func):
    @functools.wraps(func)
    async def endpoint_wrapper(*args, **kwargs):
        request = next((arg for arg in list(args) + list(kwargs.values()) if isinstance(arg, Request)), None)
        user_mfa_incomplete = request.auth.is_authenticated and not request.session.get(
            MFA_COMPLETE_SESSION_KEY
        )
        return await func(*args, user_mfa_incomplete=user_mfa_incomplete, **kwargs)

    return endpoint_wrapper
