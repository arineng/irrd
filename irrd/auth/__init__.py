import datetime
import functools
from pathlib import Path
from urllib.parse import quote_plus

import limits
import sqlalchemy.orm as saorm
import wtforms
import wtforms_bootstrap5
from asgiref.sync import sync_to_async
from markupsafe import Markup
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

import irrd
from irrd.auth.utils import get_messages
from irrd.conf import get_setting
from irrd.storage.database_handler import DatabaseHandler

UI_DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M"

RATE_LIMIT_POST_200_NAMESPACE = "irrd-http-post-200-response"
MFA_COMPLETE_SESSION_KEY = "auth-mfa-complete"


def datetime_format(value: datetime, format=UI_DEFAULT_DATETIME_FORMAT):
    return value.astimezone(datetime.UTC).strftime(format)


templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
templates.env.globals["irrd_version"] = irrd.__version__
templates.env.filters["datetime_format"] = datetime_format

FAILED_AUTH_RATE_LIMIT = limits.parse("30/hour")


class ORMSessionProvider:
    def __init__(self):
        self.database_handler = DatabaseHandler()
        self.session = self._get_session()

    def _get_session(self):
        return saorm.Session(bind=self.database_handler._connection)

    def get_database_handler(self):
        if not self.database_handler:
            self.database_handler = DatabaseHandler()
        return self.database_handler

    def commit_close(self):
        self.session.commit()
        self.database_handler.commit()
        self.session.close()
        self.database_handler.close()

    @sync_to_async
    def run(self, target):
        return self.run_sync(target)

    def run_sync(self, target):
        try:
            return target()
        except saorm.exc.NoResultFound:
            return None
        except SQLAlchemyError:
            self.get_database_handler().refresh_connection()
            target.__self__.session = self.session = self._get_session()
            return target()


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
                redir_url = request.url_for("ui:login") + "?next=" + next_redir
                return RedirectResponse(redir_url, status_code=302)

            if mfa_check and not request.session.get(MFA_COMPLETE_SESSION_KEY):
                redir_url = request.url_for("ui:mfa_authenticate") + "?next=" + next_redir
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


def template_context_render(template_name, request, context):
    context["auth_sources"] = [
        name for name, settings in get_setting("sources").items() if settings.get("authoritative")
    ]
    context["messages"] = get_messages(request)

    context["request"] = request
    if "user" not in context:
        context["user"] = request.auth.user if request.auth.is_authenticated else None
    return templates.TemplateResponse(template_name, context)


def render_form(form) -> Markup:
    checkboxes = [field.name for field in form if isinstance(field.widget, wtforms.widgets.CheckboxInput)]
    submits = [field.name for field in form if isinstance(field.widget, wtforms.widgets.SubmitInput)]
    return (
        wtforms_bootstrap5.RendererContext()
        .form()
        .default_field(
            row_class="row mb-3",
            label_class="form-label col-sm-3 col-form-label",
            field_wrapper_class="col-sm-9",
            field_wrapper_enabled=True,
        )
        .field(
            *checkboxes,
            wrapper_class="offset-sm-3 col-sm-9",
            wrapper_enabled=True,
            field_wrapper_enabled=False,
        )
        .field(
            *submits,
            field_wrapper_class="offset-sm-3 col-sm-9",
            field_wrapper_enabled=True,
        )
    ).render(form)
