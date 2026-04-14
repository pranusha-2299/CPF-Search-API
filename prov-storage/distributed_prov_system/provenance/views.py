import copy
import datetime
import json
import requests
from neomodel import db

import provenance.controller as controller
from distributed_prov_system.settings import config
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from neomodel.exceptions import DoesNotExist

from provenance.prov_doc_validators_strategies import ProvValidatorWithNormalization, ProvValidatorExternal
from provenance.prov2neomodel import import_graph

from provenance.validators import (
    InputGraphChecker,
    graph_exists,
    check_graph_id_belongs_to_meta,
    ConnectorReferenceInvalidError,
    HasNoBundles,
    TooManyBundles,
    DocumentError,
    is_org_registered,
    InvalidTrustedParty,
    UncheckedTrustedParty,
    OrganizationNotRegistered,
    check_organization_is_registered,
    send_signature_verification_request,
)

PROV_VALIDATOR = ProvValidatorExternal()


# ---------------------------------------------------------------------------
# Helper: standardized error response matching Java's error DTOs
# Java returns: {"message": "...", "status": 400}
# ---------------------------------------------------------------------------
def _error_response(message, status_code):
    return JsonResponse(
        {"message": message, "status": status_code},
        status=status_code,
    )


# ---------------------------------------------------------------------------
# Helper: build OrganizationResponseDTO matching Java's OrganizationResponseDTO
# Java returns: {"identifier": "ORG1", "clientCertificate": "...", "intermediateCertificates": [...]}
# ---------------------------------------------------------------------------
def _org_response_dto(organization_id, client_cert, intermediate_certs):
    return {
        "identifier": organization_id,
        "clientCertificate": client_cert,
        "intermediateCertificates": intermediate_certs,
    }


# ---------------------------------------------------------------------------
# Helper: extract trustedPartyUri from request body
# Java uses camelCase "trustedPartyUri", old Python used PascalCase "TrustedPartyUri"
# Accept both for transition, but prefer the Java convention.
# ---------------------------------------------------------------------------
def _get_trusted_party_uri(json_data):
    return json_data.get("trustedPartyUri") or json_data.get("TrustedPartyUri")


def get_dummy_token(organization_id="ORG"):
    return {
        "data": {
            "originatorId": organization_id,
            "authorityId": "TrustedParty",
            "tokenTimestamp": 0,
            "messageTimestamp": 0,
            "documentDigest": "17fd7484d7cac628cfa43c348fe05a009a81d18c8a778e6488b707954addf2a3",
        },
        "signature": "bdysXEy2/sOSTN+Lh+v3x7cTdocMcndwuW5OT2wHpQOU/LM4os9Bow0sn4HTln9hRqFdCMukV6Cr6Nn8XvD96jlgEw9KqJj9I+cfBL81x9iqUJX/Wder3lkuIZXYUSeGsOOqUPdlqJAhapgr0V+vibAvPGoiRKqulNi/Xn0jn21lln1HEbHPsnOtM5Ca5wwXuTITJsiXCj+04y9V/XM9Uy9Ib4LLA1VYLCdifjg0ZuxJBcpS/HszlwW9B29rrkUGUsSrV9YU0ViYkeIMcS2bMXsur3EHi3/zSZ5IepUNOBDTu3BDUr33dbrgMOVraI8RU5DTZKmUOx8hzgtApZNotg==",
    }


# ===========================================================================
# ORGANIZATION ENDPOINTS
# Matches Java: OrganizationController
#   POST /api/v1/organizations        -> createOrganization
#   GET  /api/v1/organizations         -> getAllOrganizations
#   GET  /api/v1/organizations/<id>    -> getOrganizationByIdentifier
#   PUT  /api/v1/organizations/<id>    -> updateOrganization
# ===========================================================================

@csrf_exempt
@require_http_methods(["POST", "GET"])
def organizations(request):
    """Handles POST (create) and GET (list all) for organizations."""
    if request.method == "POST":
        return _create_organization(request)
    else:
        return _list_organizations(request)


@csrf_exempt
@require_http_methods(["GET", "PUT"])
def organization_detail(request, identifier):
    """Handles GET (detail) and PUT (update) for a single organization."""
    if request.method == "GET":
        return _get_organization(request, identifier)
    else:
        return _update_organization(request, identifier)


def _create_organization(request):
    """
    POST /api/v1/organizations
    Matches Java: OrganizationController.createOrganization(OrganizationFormDTO)

    Body: {"identifier": "ORG1", "clientCertificate": "...",
           "intermediateCertificates": [...], "trustedPartyUri": "...", "clearancePeriod": 3600}
    Returns 201: OrganizationResponseDTO
    """
    if config.disable_tp:
        return _error_response("Registration is disabled when Trusted Party is disabled.", 400)

    json_data = json.loads(request.body)

    # Validate required fields (matching Java's @NotBlank/@NotNull/@NotEmpty)
    for field in ("identifier", "clientCertificate", "intermediateCertificates"):
        if field not in json_data or not json_data[field]:
            return _error_response(f"{field} should not be null or empty.", 400)

    organization_id = json_data["identifier"]

    if is_org_registered(organization_id):
        return _error_response(
            f"Organization with identifier {organization_id} already exists.",
            409,
        )

    resp = _send_register_request_to_tp(json_data, organization_id)
    if not resp.ok:
        return _error_response("Trusted party was unable to verify certificate chain.", 401)

    tp_uri = _get_trusted_party_uri(json_data)
    controller.create_and_store_organization(
        organization_id,
        json_data["clientCertificate"],
        json_data["intermediateCertificates"],
        tp_uri,
    )

    return JsonResponse(
        _org_response_dto(
            organization_id,
            json_data["clientCertificate"],
            json_data["intermediateCertificates"],
        ),
        status=201,
    )


def _list_organizations(request):
    """
    GET /api/v1/organizations
    Matches Java: OrganizationController.getAllOrganizations()
    Returns 200: list of OrganizationResponseDTO
    """
    orgs = controller.get_all_organizations()
    return JsonResponse(orgs, safe=False)


def _get_organization(request, identifier):
    """
    GET /api/v1/organizations/<identifier>
    Matches Java: OrganizationController.getOrganizationByIdentifier(uuid)
    Returns 200: OrganizationResponseDTO
    """
    org = controller.get_organization_detail(identifier)
    if org is None:
        return _error_response(f"Organization with identifier '{identifier}' does not exist.", 404)
    return JsonResponse(org)


def _update_organization(request, identifier):
    """
    PUT /api/v1/organizations/<identifier>
    Matches Java: OrganizationController.updateOrganization(uuid, OrganizationFormDTO)
    Returns 200: OrganizationResponseDTO
    """
    if config.disable_tp:
        return _error_response("Registration is disabled when Trusted Party is disabled.", 400)

    if not is_org_registered(identifier):
        return _error_response(f"Organization with identifier '{identifier}' does not exist.", 404)

    json_data = json.loads(request.body)

    for field in ("clientCertificate", "intermediateCertificates"):
        if field not in json_data or not json_data[field]:
            return _error_response(f"{field} should not be null or empty.", 400)

    resp = _send_register_request_to_tp(json_data, identifier, is_post=False)
    if not resp.ok:
        return _error_response("Trusted party was unable to verify certificate chain.", 401)

    tp_uri = _get_trusted_party_uri(json_data)
    controller.modify_organization(
        identifier,
        json_data["clientCertificate"],
        json_data["intermediateCertificates"],
        tp_uri,
    )

    return JsonResponse(
        _org_response_dto(
            identifier,
            json_data["clientCertificate"],
            json_data["intermediateCertificates"],
        ),
        status=200,
    )


def _send_register_request_to_tp(payload, organization_id, is_post=True):
    tp_url = _get_trusted_party_uri(payload) or config.tp_fqdn
    url = "http://" + tp_url + f"/api/v1/organizations/{organization_id}"
    payload["organizationId"] = organization_id

    if is_post:
        resp = requests.post(url, json.dumps(payload))
    else:
        resp = requests.put(url, json.dumps(payload))

    return resp


# ===========================================================================
# DOCUMENT ENDPOINTS
# Matches Java: DocumentController
#   POST /api/v1/documents                          -> createProvDocument
#   GET  /api/v1/documents/<identifier>              -> getFinalizedProvDocumentByIdentifier
#   HEAD /api/v1/documents/<identifier>              -> exists
#   GET  /api/v1/documents/<identifier>/domain-specific -> getDomainProvDocumentByIdentifier
#   GET  /api/v1/documents/<identifier>/backbone     -> getBackboneProvDocumentByIdentifier
# ===========================================================================

@csrf_exempt
@require_http_methods(["POST"])
def documents_create(request):
    """
    POST /api/v1/documents
    Matches Java: DocumentController.createProvDocument(DocumentFormDTO)

    Body: {"organizationIdentifier": "ORG1", "document": "<base64>",
           "documentFormat": "JSON", "signature": "...", "createdOn": 1234567890}
    Returns 201: TokenResponseDTO
    """
    json_data = json.loads(request.body)

    # Validate required fields (matching Java's @NotBlank/@NotNull)
    for field in ("organizationIdentifier", "document", "documentFormat", "signature", "createdOn"):
        if field not in json_data or json_data[field] is None:
            return _error_response(f"{field} should not be null or empty.", 400)

    organization_id = json_data["organizationIdentifier"]

    # Normalize format to lowercase for internal use (Java accepts "JSON" uppercase)
    doc_format = json_data["documentFormat"].lower()

    url_requested = request.get_full_path()
    validator = InputGraphChecker(json_data["document"], doc_format, url_requested, PROV_VALIDATOR)

    # Parse the graph to extract the bundle identifier
    if (parse_error := _parse_input_graph(validator)) is not None:
        return parse_error

    # Extract document_id from the bundle's local part (like Java does)
    document_id = validator.get_bundle_id()

    # Run validation (org check, signature verification, etc.)
    if validation_error := _validate_request(
            json_data, validator, document_id, organization_id, False, config.disable_tp
    ):
        return validation_error

    if not config.disable_tp:
        tp_url = controller.get_tp_url_by_organization(organization_id)
        payload = json_data.copy()
        payload["organizationId"] = organization_id
        payload["type"] = "graph"
        payload["graphId"] = document_id
        token = controller.send_token_request_to_tp(payload, tp_url)
    else:
        token = get_dummy_token(organization_id)

    document = validator.get_document()
    import_graph(
        document,
        json_data,
        copy.deepcopy(token),
        validator.get_meta_provenance_id(),
        document_id,
        False,
    )

    if not config.disable_tp:
        token2, neo_document, trusted_party = controller.get_token_to_store_into_db(token, document_id)
        with db.transaction:
            controller.store_token_into_db(token2, neo_document, trusted_party)
        response = token
    else:
        response = get_dummy_token(organization_id)

    return JsonResponse(response, status=201)


@csrf_exempt
@require_http_methods(["GET", "HEAD"])
def document_by_id(request, identifier):
    """
    GET  /api/v1/documents/<identifier> -> getFinalizedProvDocumentByIdentifier
    HEAD /api/v1/documents/<identifier> -> exists
    """
    if request.method == "HEAD":
        if controller.bundle_exists(identifier):
            return HttpResponse(status=200)
        return HttpResponseNotFound()

    # GET - retrieve document
    try:
        d = controller.get_document_by_identifier(identifier)
        if not config.disable_tp:
            t = controller.get_token_by_document_identifier(identifier, d)
    except DoesNotExist:
        return _error_response(f"Document with identifier '{identifier}' does not exist.", 404)

    if not config.disable_tp:
        response = {"document": d.graph, "token": t}
    else:
        response = {"document": d.graph}

    return JsonResponse(response)


@csrf_exempt
@require_http_methods(["GET"])
def document_domain_specific(request, identifier):
    """
    GET /api/v1/documents/<identifier>/domain-specific
    Matches Java: DocumentController.getDomainProvDocumentByIdentifier
    """
    return _get_subgraph(request, identifier, is_domain_specific=True)


@csrf_exempt
@require_http_methods(["GET"])
def document_backbone(request, identifier):
    """
    GET /api/v1/documents/<identifier>/backbone
    Matches Java: DocumentController.getBackboneProvDocumentByIdentifier
    """
    return _get_subgraph(request, identifier, is_domain_specific=False)


def _get_subgraph(request, identifier, is_domain_specific):
    requested_format = request.GET.get("format", "json").lower()

    if requested_format not in ("rdf", "json", "xml", "provn"):
        return _error_response(f"Requested format [{requested_format}] is not supported.", 400)

    # Resolve the organization from the document
    try:
        organization_id = controller.get_org_id_by_document_identifier(identifier)
    except DoesNotExist:
        return _error_response(f"Document with identifier '{identifier}' does not exist.", 404)

    try:
        g, t = controller.query_db_for_subgraph(
            organization_id, identifier, requested_format, is_domain_specific
        )
    except DoesNotExist:
        try:
            g = controller.get_b64_encoded_subgraph(
                organization_id, identifier, is_domain_specific, requested_format
            )

            if not config.disable_tp:
                tp_url = controller.get_tp_url_by_organization(organization_id)
                payload = {
                    "document": g,
                    "createdOn": int(datetime.datetime.now().timestamp()),
                    "type": "domain_specific" if is_domain_specific else "backbone",
                    "organizationId": organization_id,
                    "documentFormat": requested_format,
                    "graphId": identifier,
                    "doc_format": requested_format,
                }
                t = controller.send_token_request_to_tp(payload, tp_url)
            else:
                t = None

            suffix = "domain" if is_domain_specific else "backbone"
            controller.store_subgraph_into_db(
                f"{identifier}_{suffix}", requested_format, g, t
            )
        except DoesNotExist:
            return _error_response(f"Document with identifier '{identifier}' does not exist.", 404)

    if not config.disable_tp:
        response = {"document": g, "token": t}
    else:
        response = {"document": g}

    return JsonResponse(response)


# ===========================================================================
# META DOCUMENT ENDPOINT
# Matches Java: MetaDocumentController
#   HEAD /api/v1/documents/meta/<uuid>  -> exists
# Java only has HEAD (no GET), so we only support HEAD.
# ===========================================================================

@csrf_exempt
@require_http_methods(["HEAD"])
def meta_document(request, uuid):
    """
    HEAD /api/v1/documents/meta/<uuid>
    Matches Java: MetaDocumentController.exists(uuid)
    """
    if controller.meta_bundle_exists(uuid):
        return HttpResponse(status=200)
    return HttpResponseNotFound()


# ===========================================================================
# INTERNAL VALIDATION HELPERS (kept from original, used by document creation)
# ===========================================================================

def _validate_request_fields(request_json, mandatory_fields):
    for field in mandatory_fields:
        if field not in request_json:
            return _error_response(f"Mandatory field [{field}] not present in request.", 400)
    return None


def _validate_request(
        json_data, validator, document_id, organization_id, is_update, disable_tp
):
    expected_json_fields = ("document", "documentFormat")
    if not disable_tp:
        try:
            check_organization_is_registered(organization_id)
        except (InvalidTrustedParty, UncheckedTrustedParty, OrganizationNotRegistered) as e:
            return _error_response(str(e), 404)
        expected_json_fields = ("document", "signature", "documentFormat", "createdOn")
        tp_url = controller.get_tp_url_by_organization(organization_id)
        resp = send_signature_verification_request(
            json_data.copy(), organization_id, tp_url
        )
        if not resp.ok:
            return _error_response(
                "Unverifiable signature. Make sure to register your certificate with trusted party first.",
                401,
            )

    if (missing_field_error := _validate_request_fields(json_data, expected_json_fields)) is not None:
        return missing_field_error

    if not is_update:
        if (new_doc_error := _validate_new_document_conditions(validator, document_id)) is not None:
            return new_doc_error

    if (dup_error := _validate_duplicate_bundle(validator, document_id, organization_id)) is not None:
        return dup_error

    try:
        validator.validate_graph()
    except (ConnectorReferenceInvalidError, HasNoBundles, TooManyBundles, DocumentError) as e:
        return _error_response(str(e), 400)

    return None


def _validate_new_document_conditions(validator, document_id):
    try:
        validator.check_ids_match(document_id)
    except DocumentError as e:
        return _error_response(str(e), 400)


def _parse_input_graph(validator):
    try:
        validator.parse_graph()
    except DocumentError as e:
        return _error_response(str(e), 400)


def _validate_duplicate_bundle(validator, document_id, organization_id):
    if graph_exists(organization_id, validator.get_bundle_id()):
        return _error_response(
            f"Document with identifier '{validator.get_bundle_id()}' already exists.",
            409,
        )
