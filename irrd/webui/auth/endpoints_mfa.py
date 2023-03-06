import base64
from datetime import datetime, timezone

import pyotp
import webauthn
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette_wtf import csrf_protect
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
)
from wtforms_bootstrap5 import RendererContext

from irrd.storage.models import AuthWebAuthn
from irrd.storage.orm_provider import ORMSessionProvider
from irrd.webui import MFA_COMPLETE_SESSION_KEY
from irrd.webui.auth.decorators import authentication_required
from irrd.webui.auth.endpoints import (
    TOTP_REGISTRATION_SECRET_SESSION_KEY,
    WN_CHALLENGE_SESSION_KEY,
    WN_ORIGIN,
    WN_RP_ID,
    WN_RP_NAME,
    TOTPAuthenticateForm,
    TOTPRegisterForm,
    TOTPRemoveForm,
    WebAuthnRemoveForm,
    clean_next_url,
)
from irrd.webui.helpers import message, rate_limit_post_200, session_provider_manager
from irrd.webui.rendering import render_form, template_context_render


@authentication_required
async def mfa_status(request: Request) -> Response:
    context = {
        "has_mfa": request.auth.user.has_mfa,
        "has_totp": request.auth.user.has_totp,
        "webauthns": request.auth.user.webauthns,
    }
    return template_context_render("mfa_status.html", request, context)


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
