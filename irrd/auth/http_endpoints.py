from collections import defaultdict
from typing import Optional

from asgiref.sync import sync_to_async
from starlette.requests import Request
from starlette.responses import Response
from starlette_wtf import csrf_protect, csrf_token

from irrd.storage.models import AuthUser, RPSLDatabaseObject
from irrd.storage.queries import RPSLDatabaseQuery
from irrd.updates.handler import ChangeSubmissionHandler

from ..conf import get_setting
from ..utils.text import remove_auth_hashes
from . import (
    ORMSessionProvider,
    authentication_required,
    mark_user_mfa_incomplete,
    session_provider_manager,
    template_context_render,
)


async def index(request: Request) -> Response:
    mirrored_sources = [
        name for name, settings in get_setting("sources").items() if not settings.get("authoritative")
    ]
    return template_context_render(
        "index.html",
        request,
        {"mirrored_sources": mirrored_sources},
    )


@session_provider_manager
@authentication_required
async def maintained_objects(request: Request, session_provider: ORMSessionProvider) -> Response:
    user_mntners = [
        (mntner.rpsl_mntner_pk, mntner.rpsl_mntner_source) for mntner in request.auth.user.mntners
    ]
    if not user_mntners:
        return template_context_render(
            "maintained_objects.html",
            request,
            {
                "objects": None,
            },
        )
    user_mntbys, user_sources = zip(*user_mntners)
    q = RPSLDatabaseQuery().lookup_attrs_in(["mnt-by"], user_mntbys).sources(user_sources)
    query_result = session_provider.database_handler.execute_query(q)
    objects = filter(
        lambda obj: any([(mntby, obj["source"]) in user_mntners for mntby in obj["parsed_data"]["mnt-by"]]),
        query_result,
    )

    return template_context_render(
        "maintained_objects.html",
        request,
        {
            "objects": objects,
        },
    )


@mark_user_mfa_incomplete
@session_provider_manager
async def rpsl_detail(request: Request, user_mfa_incomplete: bool, session_provider: ORMSessionProvider):
    if request.method == "GET":
        if all([key in request.path_params for key in ["rpsl_pk", "object_class", "source"]]):
            query = session_provider.session.query(RPSLDatabaseObject).filter(
                RPSLDatabaseObject.rpsl_pk == str(request.path_params["rpsl_pk"].upper()),
                RPSLDatabaseObject.object_class == str(request.path_params["object_class"].lower()),
                RPSLDatabaseObject.source == str(request.path_params["source"].upper()),
            )
            rpsl_object = await session_provider.run(query.one)
        else:
            return Response("Missing search parameter", status_code=400)
        rpsl_object.object_text_display = filter_auth_hash_non_mntner(
            None if user_mfa_incomplete else request.auth.user, rpsl_object
        )

        return template_context_render(
            "rpsl_detail.html",
            request,
            {
                "object": rpsl_object,
            },
        )


@csrf_protect
@mark_user_mfa_incomplete
@session_provider_manager
async def rpsl_update(
    request: Request, user_mfa_incomplete: bool, session_provider: ORMSessionProvider
) -> Response:
    mntner_perms = defaultdict(list)
    if not user_mfa_incomplete and request.auth.is_authenticated:
        for mntner in request.auth.user.mntners_user_management:
            mntner_perms[mntner.rpsl_mntner_source].append((mntner.rpsl_mntner_pk, True))
        for mntner in request.auth.user.mntners_no_user_management:
            mntner_perms[mntner.rpsl_mntner_source].append((mntner.rpsl_mntner_pk, False))

    if request.method == "GET":
        existing_data = ""
        if all([key in request.path_params for key in ["rpsl_pk", "object_class", "source"]]):
            query = session_provider.session.query(RPSLDatabaseObject).filter(
                RPSLDatabaseObject.rpsl_pk == str(request.path_params["rpsl_pk"].upper()),
                RPSLDatabaseObject.object_class == str(request.path_params["object_class"].lower()),
                RPSLDatabaseObject.source == str(request.path_params["source"].upper()),
            )
            obj = await session_provider.run(query.one)
            if obj:
                existing_data = filter_auth_hash_non_mntner(request.auth.user, obj)

        return template_context_render(
            "rpsl_form.html",
            request,
            {
                "existing_data": existing_data,
                "status": None,
                "report": None,
                "mntner_perms": mntner_perms,
                "csrf_token": csrf_token(request),
            },
        )

    elif request.method == "POST":
        form_data = await request.form()
        request_meta = {
            "HTTP-client-IP": request.client.host,
            "HTTP-User-Agent": request.headers.get("User-Agent"),
        }

        # ChangeSubmissionHandler builds its own DB connection
        # and therefore needs wrapping in a thread
        @sync_to_async
        def save():
            return ChangeSubmissionHandler().load_text_blob(
                object_texts_blob=form_data["data"],
                request_meta=request_meta,
                internal_authenticated_user=request.auth.user if request.auth.is_authenticated else None,
            )

        handler = await save()
        return template_context_render(
            "rpsl_form.html",
            request,
            {
                "existing_data": form_data["data"],
                "status": handler.status(),
                "report": handler.submitter_report_human(),
                "mntner_perms": mntner_perms,
                "csrf_token": csrf_token(request),
            },
        )
    return Response(status_code=405)  # pragma: no cover


@session_provider_manager
@authentication_required
async def user_detail(request: Request, session_provider: ORMSessionProvider) -> Response:
    # The user detail page needs a rich and bound instance of AuthUser
    query = session_provider.session.query(AuthUser).filter_by(email=request.auth.user.email)
    bound_user = await session_provider.run(query.one)
    return template_context_render("user_detail.html", request, {"user": bound_user})


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
