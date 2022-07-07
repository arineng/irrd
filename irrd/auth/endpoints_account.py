import base64
import secrets
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote_plus, urlparse

import pyotp
import webauthn
import wtforms
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette_wtf import StarletteForm, csrf_protect
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
)
from wtforms_bootstrap5 import RendererContext

from ..storage.models import AuthUser, AuthWebAuthn
from . import (
    MFA_COMPLETE_SESSION_KEY,
    ORMSessionProvider,
    authentication_required,
    rate_limit_post_200,
    render_form,
    session_provider_manager,
    template_context_render,
)
from .auth import CurrentPasswordForm, login_manager, password_handler
from .utils import AuthUserToken, message, send_template_email

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


@authentication_required
async def webauthn_register(request: Request) -> Response:
    existing_credentials = [
        PublicKeyCredentialDescriptor(id=auth.credential_id) for auth in request.auth.user.webauthns
    ]

    options = webauthn.generate_registration_options(
        rp_name=WN_RP_NAME,
        rp_id=WN_RP_ID,
        # An assigned random identifier;
        # never anything user-identifying like an email address
        user_id=str(request.auth.user.pk),
        # A user-visible hint of which account this credential belongs to
        user_name=request.auth.user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=existing_credentials,
    )

    # Remember the challenge for later, you'll need it in the next step
    request.session[WN_CHALLENGE_SESSION_KEY] = base64.b64encode(options.challenge).decode("ascii")

    webauthn_options_json = webauthn.options_to_json(options)
    return template_context_render(
        "webauthn_register.html", request, {"webauthn_options_json": webauthn_options_json}
    )


@session_provider_manager
@authentication_required
# No CSRF protection needed: protected by webauthn challenge
async def webauthn_verify_registration_response(
    request: Request, session_provider: ORMSessionProvider
) -> Response:
    try:
        expected_challenge = base64.b64decode(request.session[WN_CHALLENGE_SESSION_KEY])
        body = await request.json()
        credential = RegistrationCredential.parse_raw(body["registration_response"])
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=WN_RP_ID,
            expected_origin=WN_ORIGIN,
            require_user_verification=False,
        )
    except Exception as err:
        print(err)
        return JSONResponse({"success": False})

    new_auth = AuthWebAuthn(
        user_id=str(request.auth.user.pk),
        name=body["name"],
        credential_id=verification.credential_id,
        credential_public_key=verification.credential_public_key,
        credential_sign_count=verification.sign_count,
    )
    session_provider.session.add(new_auth)
    del request.session[WN_CHALLENGE_SESSION_KEY]
    message(request, "Your security token has been added to your account. You may need to re-authenticate.")
    return JSONResponse({"success": True})


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


@rate_limit_post_200
@authentication_required(mfa_check=False)
@session_provider_manager
async def mfa_authenticate(request: Request, session_provider: ORMSessionProvider) -> Response:
    next_url = clean_next_url(request)
    webauthn_options_json = None
    totp_form_html = None

    if request.auth.user.has_webauthn:
        credentials = [
            PublicKeyCredentialDescriptor(id=auth.credential_id) for auth in request.auth.user.webauthns
        ]
        options = webauthn.generate_authentication_options(
            rp_id=WN_RP_ID,
            user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=credentials,
        )

        request.session[WN_CHALLENGE_SESSION_KEY] = base64.b64encode(options.challenge).decode("ascii")
        webauthn_options_json = webauthn.options_to_json(options)

    if request.auth.user.has_totp:
        totp = pyotp.totp.TOTP(request.auth.user.totp_secret)
        form = await TOTPAuthenticateForm.from_formdata(request=request)
        if form.is_submitted() and await form.validate(totp=totp, last_used=request.auth.user.totp_last_used):
            try:
                del request.session[WN_CHALLENGE_SESSION_KEY]
            except KeyError:
                pass
            request.session[MFA_COMPLETE_SESSION_KEY] = True
            request.auth.user.totp_last_used = form.token.data
            session_provider.session.add(request.auth.user)
            return RedirectResponse(next_url, status_code=302)
        else:
            # Intentional non-horizontal form for consistency with WebAuthn button
            totp_form_html = RendererContext().render(form)

    return template_context_render(
        "mfa_authenticate.html",
        request,
        {
            "has_totp": request.auth.user.has_totp,
            "has_webauthn": request.auth.user.has_webauthn,
            "webauthn_options_json": webauthn_options_json,
            "totp_form_html": totp_form_html,
            "next": next_url,
        },
    )


@session_provider_manager
@authentication_required(mfa_check=False)
# No CSRF protection needed: protected by webauthn challenge
async def webauthn_verify_authentication_response(
    request: Request, session_provider: ORMSessionProvider
) -> Response:
    try:
        expected_challenge = base64.b64decode(request.session[WN_CHALLENGE_SESSION_KEY])
        credential = AuthenticationCredential.parse_raw(await request.body())
        query = session_provider.session.query(AuthWebAuthn).filter_by(
            user=request.auth.user, credential_id=credential.raw_id
        )
        authn = await session_provider.run(query.one)

        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=WN_RP_ID,
            expected_origin=WN_ORIGIN,
            credential_public_key=authn.credential_public_key,
            credential_current_sign_count=authn.credential_sign_count,
            require_user_verification=False,
        )
    except Exception as err:
        print(err)
        return JSONResponse({"verified": False})

    authn.credential_sign_count = verification.new_sign_count
    authn.last_used = datetime.now(timezone.utc)
    session_provider.session.add(authn)

    del request.session[WN_CHALLENGE_SESSION_KEY]
    request.session[MFA_COMPLETE_SESSION_KEY] = True
    return JSONResponse({"verified": True})


@authentication_required
async def mfa_status(request: Request) -> Response:
    context = {
        "has_mfa": request.auth.user.has_mfa,
        "has_totp": request.auth.user.has_totp,
        "webauthns": request.auth.user.webauthns,
    }
    return template_context_render("mfa_status.html", request, context)


class WebAuthnRemoveForm(CurrentPasswordForm):
    submit = wtforms.SubmitField("Remove this security token")


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def webauthn_remove(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthWebAuthn)
    query = query.filter(
        AuthWebAuthn.pk == request.path_params["webauthn"], AuthWebAuthn.user_id == str(request.auth.user.pk)
    )
    target = await session_provider.run(query.one)

    if not target:
        return Response(status_code=404)

    form = await WebAuthnRemoveForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate(current_user=request.auth.user):
        return template_context_render(
            "webauthn_remove.html",
            request,
            {"target": target, "form_html": render_form(form)},
        )

    session_provider.session.delete(target)
    message(request, "The security token has been removed.")
    return RedirectResponse(request.url_for("ui:mfa_status"), status_code=302)


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


@authentication_required
@session_provider_manager
async def totp_register(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await TOTPRegisterForm.from_formdata(request=request)
    totp_secret = request.session.get(TOTP_REGISTRATION_SECRET_SESSION_KEY, pyotp.random_base32())
    totp = pyotp.totp.TOTP(totp_secret)

    if not form.is_submitted() or not await form.validate(current_user=request.auth.user, totp=totp):
        totp_secret = pyotp.random_base32()
        request.session[TOTP_REGISTRATION_SECRET_SESSION_KEY] = totp_secret
        totp_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=request.auth.user.email, issuer_name="IRRD on TODO"
        )

        return template_context_render(
            "totp_register.html",
            request,
            {"secret": totp_secret, "totp_url": totp_url, "form_html": render_form(form)},
        )

    request.auth.user.totp_secret = totp_secret
    session_provider.session.add(request.auth.user)
    message(request, "One time passwords have been enabled. You may need to re-authenticate.")
    return RedirectResponse(request.url_for("ui:mfa_status"), status_code=302)


class TOTPRemoveForm(CurrentPasswordForm):
    submit = wtforms.SubmitField("Remove one time password (TOTP)")


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def totp_remove(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await TOTPRemoveForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate(current_user=request.auth.user):
        return template_context_render(
            "totp_remove.html",
            request,
            {"form_html": render_form(form)},
        )

    request.auth.user.totp_secret = None
    session_provider.session.add(request.auth.user)
    message(request, "The one time password been removed.")
    return RedirectResponse(request.url_for("ui:mfa_status"), status_code=302)
