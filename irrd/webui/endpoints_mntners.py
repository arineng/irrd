import secrets
import textwrap

import wtforms
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette_wtf import StarletteForm, csrf_protect

from irrd.conf import get_setting
from irrd.rpsl.rpsl_objects import RPSLMntner
from irrd.storage.models import (
    AuthMntner,
    AuthPermission,
    AuthUser,
    JournalEntryOrigin,
    RPSLDatabaseObject,
)
from irrd.storage.orm_provider import ORMSessionProvider
from irrd.utils.email import send_email
from irrd.webui.auth.decorators import authentication_required
from irrd.webui.auth.users import CurrentPasswordForm
from irrd.webui.helpers import (
    message,
    rate_limit_post_200,
    send_template_email,
    session_provider_manager,
)
from irrd.webui.rendering import render_form, template_context_render


class PermissionAddForm(CurrentPasswordForm):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.new_user = None
        self.session_provider = session_provider

    new_user_email = wtforms.EmailField(
        "Email address of the newly authorised user",
        validators=[wtforms.validators.DataRequired()],
    )
    confirm = wtforms.BooleanField(
        "Give this user access to modify all objects maintained by this mntner",
        validators=[wtforms.validators.DataRequired()],
    )
    user_management = wtforms.BooleanField(
        (
            "Give this user access to user management, including adding and removing other users (including"
            " myself)"
        ),
    )
    submit = wtforms.SubmitField("Authorise this user")

    async def validate(self, extra_validators=None, current_user: AuthUser = None, mntner: AuthMntner = None):
        if not await super().validate(extra_validators, current_user=current_user):
            return False

        query = self.session_provider.session.query(AuthUser).filter_by(email=self.new_user_email.data)
        self.new_user = await self.session_provider.run(query.one)

        if not self.new_user:
            self.new_user_email.errors.append("Unknown user account.")
            return False

        query = self.session_provider.session.query(AuthPermission).filter_by(
            mntner=mntner, user=self.new_user
        )
        existing_perms = await self.session_provider.run(query.count)

        if existing_perms:
            self.new_user_email.errors.append("This user already has permissions on this mntner.")
            return False

        return True


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def permission_add(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthMntner).join(AuthPermission)
    query = query.filter(
        AuthMntner.pk == request.path_params["mntner"],
        AuthPermission.user_id == str(request.auth.user.pk),
        AuthPermission.user_management.is_(True),
    )
    mntner = await session_provider.run(query.one)

    if not mntner or not mntner.migration_complete:
        return Response(status_code=404)

    form = await PermissionAddForm.from_formdata(request=request, session_provider=session_provider)
    if not form.is_submitted() or not await form.validate(current_user=request.auth.user, mntner=mntner):
        form_html = render_form(form)
        return template_context_render(
            "permission_form.html", request, {"form_html": form_html, "mntner": mntner}
        )

    new_permission = AuthPermission(
        user_id=str(form.new_user.pk),
        mntner_id=str(mntner.pk),
        user_management=bool(form.user_management.data),
    )
    session_provider.session.add(new_permission)
    message_text = (
        f"A permission for {form.new_user.name} ({form.new_user.email}) on {mntner.rpsl_mntner_pk} has been"
        " added."
    )
    message(request, message_text)
    await notify_mntner(session_provider, request.auth.user, mntner, explanation=message_text)
    return RedirectResponse(request.url_for("ui:user_detail"), status_code=302)


class PermissionDeleteForm(CurrentPasswordForm):
    confirm = wtforms.BooleanField(
        "Remove this user's access to this mntner", validators=[wtforms.validators.DataRequired()]
    )
    confirm_self_delete = wtforms.BooleanField(
        "I understand I am deleting my own permission on this mntner, and will immediately lose access",
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Remove this user's authorisation")


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def permission_delete(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthPermission)
    user_mntner_pks = [perm.mntner_id for perm in request.auth.user.permissions if perm.user_management]
    query = query.filter(
        AuthPermission.pk == request.path_params["permission"],
        AuthPermission.mntner_id.in_(user_mntner_pks),
    )
    permission = await session_provider.run(query.one)

    if not permission or not permission.mntner.migration_complete:
        return Response(status_code=404)

    if len(permission.mntner.permissions) == 1:
        return template_context_render(
            "permission_delete.html", request, {"refused_last_permission": True, "permission": permission}
        )

    form = await PermissionDeleteForm.from_formdata(request=request)
    if request.auth.user != permission.user:
        del form.confirm_self_delete

    if not form.is_submitted() or not await form.validate(current_user=request.auth.user):
        form_html = render_form(form)
        return template_context_render(
            "permission_delete.html", request, {"form_html": form_html, "permission": permission}
        )

    message_text = (
        f"The permission for {permission.user.name} ({permission.user.email}) on"
        f" {permission.mntner.rpsl_mntner_pk} has been deleted."
    )
    await notify_mntner(session_provider, request.auth.user, permission.mntner, explanation=message_text)
    session_provider.session.query(AuthPermission).filter(
        AuthPermission.pk == request.path_params["permission"]
    ).delete()
    session_provider.session.commit()
    session_provider.session.close()
    message(request, message_text)
    return RedirectResponse(request.url_for("ui:user_detail"), status_code=302)


class MntnerMigrateInitiateForm(StarletteForm):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_provider = session_provider
        self.rpsl_mntner = None
        self.rpsl_mntner_db_pk = None
        auth_sources = [
            name for name, settings in get_setting("sources").items() if settings.get("authoritative")
        ]
        self.mntner_source.choices = sorted([(source, source) for source in auth_sources])

    mntner_key = wtforms.StringField(
        "Mntner name",
        description="The name (primary key) of the mntner to migrate.",
        validators=[wtforms.validators.DataRequired()],
        filters=[lambda x: x.upper() if x else None],
    )
    mntner_source = wtforms.SelectField(
        "Mntner source",
        description="The RPSL database for your mntner.",
        validators=[wtforms.validators.DataRequired()],
    )
    mntner_password = wtforms.StringField(
        "Mntner password",
        description="One of the current passwords on the mntner",
        validators=[wtforms.validators.DataRequired()],
    )
    confirm = wtforms.BooleanField(
        "I understand that this migration can not be reversed", validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Migrate this mntner")

    async def validate(self, extra_validators=None):
        if not await super().validate(extra_validators):
            return False

        query = self.session_provider.session.query(RPSLDatabaseObject).outerjoin(AuthMntner)
        query = query.filter(
            RPSLDatabaseObject.rpsl_pk == self.mntner_key.data,
            RPSLDatabaseObject.source == self.mntner_source.data,
            RPSLDatabaseObject.object_class == "mntner",
        )
        mntner_obj = await self.session_provider.run(query.one)
        if not mntner_obj:
            self.mntner_key.errors.append("Unable to find this mntner object.")
            return False
        if mntner_obj.auth_mntner:
            self.mntner_key.errors.append(
                "This maintainer was already migrated or a migration is in progress."
            )
            return False
        self.rpsl_mntner_db_pk = mntner_obj.pk
        self.rpsl_mntner = RPSLMntner(mntner_obj.object_text, strict_validation=False)

        if not self.rpsl_mntner.verify_auth(passwords=[self.mntner_password.data]):
            self.mntner_password.errors.append("Invalid password for the methods on this mntner object.")
            return False

        return True


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def mntner_migrate_initiate(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await MntnerMigrateInitiateForm.from_formdata(request=request, session_provider=session_provider)
    if not form.is_submitted() or not await form.validate():
        form_html = render_form(form)
        return template_context_render("mntner_migrate_initiate.html", request, {"form_html": form_html})

    new_auth_mntner = AuthMntner(
        rpsl_mntner_pk=form.rpsl_mntner.pk(),
        rpsl_mntner_obj_id=str(form.rpsl_mntner_db_pk),
        rpsl_mntner_source=form.mntner_source.data,
        migration_token=secrets.token_urlsafe(24),
    )
    session_provider.session.add(new_auth_mntner)
    session_provider.session.commit()

    new_permission = AuthPermission(
        user_id=str(request.auth.user.pk),
        mntner_id=str(new_auth_mntner.pk),
        user_management=True,
    )
    session_provider.session.add(new_permission)

    send_template_email("email", "mntner_migrate_initiate", request, {"auth_mntner": new_auth_mntner})
    message(request, "You have been sent a confirmation email to complete the migration.")
    return RedirectResponse(request.url_for("ui:user_detail"), status_code=302)


class MntnerMigrateCompleteForm(StarletteForm):
    def __init__(self, *args, auth_mntner: AuthMntner, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_mntner = auth_mntner
        self.rpsl_mntner_obj = None

    mntner_password = wtforms.StringField(
        "Mntner password",
        description="One of the current passwords on the mntner",
        validators=[wtforms.validators.DataRequired()],
    )
    confirm = wtforms.BooleanField(
        "I understand that this migration can not be reversed", validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Migrate this mntner")

    async def validate(self, extra_validators=None):
        if not await super().validate(extra_validators):
            return False

        self.rpsl_mntner_obj = RPSLMntner(
            self.auth_mntner.rpsl_mntner_obj.object_text, strict_validation=False
        )
        if not self.rpsl_mntner_obj.verify_auth(passwords=[self.mntner_password.data]):
            self.mntner_password.errors.append("Invalid password for the methods on this mntner object.")
            return False

        return True


@rate_limit_post_200
@csrf_protect
@session_provider_manager
@authentication_required
async def mntner_migrate_complete(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthMntner).join(AuthPermission)
    query = query.filter(
        AuthMntner.pk == str(request.path_params["pk"]),
        AuthMntner.migration_token == request.path_params["token"],
        AuthPermission.user_id == str(request.auth.user.pk),
        AuthPermission.user_management.is_(True),
    )
    auth_mntner = await session_provider.run(query.one)

    if not auth_mntner:
        return Response(status_code=404)
    form = await MntnerMigrateCompleteForm.from_formdata(request=request, auth_mntner=auth_mntner)
    if not form.is_submitted() or not await form.validate():
        form_html = render_form(form)
        return template_context_render(
            "mntner_migrate_complete.html", request, {"form_html": form_html, "auth_mntner": auth_mntner}
        )

    form.auth_mntner.migration_token = None
    session_provider.session.add(form.auth_mntner)

    form.rpsl_mntner_obj.add_irrd_internal_auth()
    session_provider.database_handler.upsert_rpsl_object(
        form.rpsl_mntner_obj, origin=JournalEntryOrigin.unknown
    )

    msg = textwrap.dedent(
        """
        The maintainer has been migrated to IRRD internal authentication.
        Existing authentication methods have been kept. 
    """
    )
    await notify_mntner(session_provider, request.auth.user, auth_mntner, explanation=msg)

    message(request, f"The mntner {auth_mntner.rpsl_mntner_pk} has been migrated.")
    return RedirectResponse(request.url_for("ui:user_detail"), status_code=302)


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
