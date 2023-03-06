import secrets
from typing import Optional
from urllib.parse import unquote_plus, urlparse

import pyotp
import wtforms
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette_wtf import StarletteForm, csrf_protect

from irrd.storage.models import AuthUser
from irrd.storage.orm_provider import ORMSessionProvider
from irrd.webui import MFA_COMPLETE_SESSION_KEY
from irrd.webui.auth.decorators import authentication_required
from irrd.webui.auth.users import (
    AuthUserToken,
    CurrentPasswordForm,
    login_manager,
    password_handler,
)
from irrd.webui.helpers import (
    message,
    rate_limit_post_200,
    send_template_email,
    session_provider_manager,
)
from irrd.webui.rendering import render_form, template_context_render

TOTP_REGISTRATION_SECRET_SESSION_KEY = "totp_registration_secret"
WN_CHALLENGE_SESSION_KEY = "webauthn_current_challenge"

WN_RP_NAME = "IRRD"

WN_ORIGIN = "http://localhost:8000"

WN_RP_ID = "localhost"

LOGIN_REDIRECT_DEFAULT = "ui:index"


def clean_next_url(request: Request, default: str = LOGIN_REDIRECT_DEFAULT):
    # To prevent an open redirect, this discards everything except the
    # path from the next parameter. Not very flexible, but sufficient
    # for IRRD needs.
    next_param = unquote_plus(request.query_params.get("next", ""))
    _, _, next_path, _, _, _ = urlparse(next_param)
    return next_path if next_path else request.url_for(LOGIN_REDIRECT_DEFAULT)


@rate_limit_post_200
async def login(request: Request):
    if request.method == "GET":
        return template_context_render(
            "login.html",
            request,
            {
                "errors": None,
            },
        )

    if request.method == "POST":
        data = await request.form()
        email = data["email"]
        password = data["password"]

        user_token = await login_manager.login(request, email, password)

        if user_token:
            if not user_token.user.has_mfa:
                request.session[MFA_COMPLETE_SESSION_KEY] = True
            return RedirectResponse(clean_next_url(request), status_code=302)
        else:
            return template_context_render(
                "login.html",
                request,
                {
                    "errors": "Invalid account or password.",
                },
            )


async def logout(request: Request):
    await login_manager.logout(request)
    return RedirectResponse(request.url_for("ui:index"), status_code=302)


class CreateAccountForm(StarletteForm):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_provider = session_provider

    email = wtforms.EmailField(
        "Your email address",
        validators=[wtforms.validators.DataRequired()],
    )
    name = wtforms.StringField(
        "Your name",
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Create account")

    async def validate(self, extra_validators=None):
        if not await super().validate(extra_validators):
            return False

        query = self.session_provider.session.query(AuthUser).filter_by(email=self.email.data)
        if await self.session_provider.run(query.count):
            self.email.errors.append("Account already exists.")
            return False

        return True


@rate_limit_post_200
@csrf_protect
@session_provider_manager
async def create_account(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await CreateAccountForm.from_formdata(request=request, session_provider=session_provider)
    if not form.is_submitted() or not await form.validate():
        return template_context_render("create_account_form.html", request, {"form_html": render_form(form)})

    new_user = AuthUser(
        email=form.email.data,
        password=secrets.token_hex(24),
        name=form.name.data,
    )
    session_provider.session.add(new_user)
    session_provider.session.commit()

    token = AuthUserToken(new_user).generate_token()
    send_template_email(form.email.data, "create_account", request, {"user_pk": new_user.pk, "token": token})
    message(request, f"You have been sent an email to confirm your account on {form.email.data}.")
    return RedirectResponse(request.url_for("ui:index"), status_code=302)


class ResetPasswordForm(StarletteForm):
    email = wtforms.EmailField(
        "Your email address",
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Reset password")


@rate_limit_post_200
@csrf_protect
@session_provider_manager
async def reset_password(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await ResetPasswordForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate():
        return template_context_render("reset_password_form.html", request, {"form_html": render_form(form)})

    query = session_provider.session.query(AuthUser).filter_by(email=form.email.data)
    user = await session_provider.run(query.one)

    if user:
        token = AuthUserToken(user).generate_token()
        send_template_email(form.email.data, "reset_password", request, {"user_pk": user.pk, "token": token})
    message(
        request,
        f"You have been sent an email to reset your password on {form.email.data}, if this account exists.",
    )
    return RedirectResponse(request.url_for("ui:index"), status_code=302)


class ChangePasswordForm(CurrentPasswordForm):
    new_password = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    new_password_confirmation = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Change password")

    async def validate(self, extra_validators=None, current_user=None):
        if not await super().validate(extra_validators, current_user=current_user):
            return False

        if self.new_password.data != self.new_password_confirmation.data:
            self.new_password_confirmation.errors.append("Passwords do not match.")
            return False

        return True


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def change_password(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await ChangePasswordForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate(current_user=request.auth.user):
        return template_context_render(
            "password_change_form.html",
            request,
            {"form_html": render_form(form)},
        )

    request.auth.user.password = password_handler.hash(form.new_password.data)
    session_provider.session.add(request.auth.user)
    message(request, "Your password has been changed.")
    return RedirectResponse(request.url_for("ui:index"), status_code=302)


class ChangeProfileForm(CurrentPasswordForm):
    email = wtforms.EmailField(
        validators=[wtforms.validators.DataRequired()],
    )
    name = wtforms.StringField(
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Change name/email")


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def change_profile(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await ChangeProfileForm.from_formdata(
        request=request, email=request.auth.user.email, name=request.auth.user.name
    )
    if not form.is_submitted() or not await form.validate(current_user=request.auth.user):
        return template_context_render(
            "profile_change_form.html",
            request,
            {"form_html": render_form(form)},
        )

    request.auth.user.name = form.name.data
    request.auth.user.email = form.email.data
    session_provider.session.add(request.auth.user)
    message(request, "Your name/e-mail address have been changed.")
    return RedirectResponse(request.url_for("ui:index"), status_code=302)


class SetPasswordForm(StarletteForm):
    new_password = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    new_password_confirmation = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Set password")

    async def validate(self, extra_validators=None):
        if not await super().validate(extra_validators):
            return False

        if self.new_password.data != self.new_password_confirmation.data:
            self.new_password_confirmation.errors.append("Passwords do not match.")
            return False

        return True


@csrf_protect
@session_provider_manager
async def set_password(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthUser).filter(
        AuthUser.pk == request.path_params["pk"],
    )
    user = await session_provider.run(query.one)

    if not user or not AuthUserToken(user).validate_token(request.path_params["token"]):
        return Response(status_code=404)

    # get user and check token
    # session_provider.session.add(new_user)
    form = await SetPasswordForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate():
        return template_context_render(
            "create_account_confirm_form.html",
            request,
            {"form_html": render_form(form), "initial": request.path_params.get("initial")},
        )

    user.password = password_handler.hash(form.new_password.data)
    session_provider.session.add(user)
    message(request, "Your password has been changed.")
    return RedirectResponse(request.url_for("ui:login"), status_code=302)


class TOTPAuthenticateForm(StarletteForm):
    token = wtforms.StringField(
        label="Enter the current token from your app",
        validators=[wtforms.validators.InputRequired()],
    )
    submit = wtforms.SubmitField("Authenticate with one time password")

    async def validate(
        self, extra_validators=None, totp: Optional[pyotp.totp.TOTP] = None, last_used: Optional[str] = None
    ):
        if not await super().validate(extra_validators):
            return False

        self.token.data = self.token.data.replace(" ", "")

        if not totp.verify(self.token.data):
            self.token.errors.append("Incorrect token.")
            return False

        if self.token.data == last_used:
            self.token.errors.append("Token already used. Wait for the next token.")
            return False

        return True


class WebAuthnRemoveForm(CurrentPasswordForm):
    submit = wtforms.SubmitField("Remove this security token")


class TOTPRegisterForm(CurrentPasswordForm):
    token = wtforms.StringField(
        label="Enter the current token from your app",
        validators=[wtforms.validators.InputRequired()],
    )
    submit = wtforms.SubmitField("Enable one time password")

    async def validate(
        self,
        extra_validators=None,
        current_user: Optional[AuthUser] = None,
        totp: Optional[pyotp.totp.TOTP] = None,
    ):
        if not await super().validate(extra_validators, current_user):
            return False

        if not totp.verify(self.token.data.replace(" ", "")):
            self.token.errors.append("Incorrect token.")
            return False

        return True


class TOTPRemoveForm(CurrentPasswordForm):
    submit = wtforms.SubmitField("Remove one time password (TOTP)")
