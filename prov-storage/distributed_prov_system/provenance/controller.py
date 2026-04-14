import base64
import json

from provenance.is_backbone_entity_strategies import IsBackboneStrategyOriginal
from provenance.CPM_helpers import get_backbone_and_domain
from provenance.models import (
    Document,
    Bundle,
    Token,
    Organization,
    TrustedParty,
    DefaultTrustedParty,
)
from provenance.neomodel2prov import convert_meta_to_prov
import prov.model as provm
from base64 import b64decode, b64encode
from neomodel.exceptions import DoesNotExist
from neomodel import db
from distributed_prov_system.settings import config
import requests
import re

from provenance.constants import CPM_REFERENCED_BUNDLE_ID, CPM_REFERENCED_META_BUNDLE_ID

# change strategy for is_backbone - decides whether entity belongs to traversal information or not - in case of new strategy add a endpoint for changing it
IS_BACKBONE = IsBackboneStrategyOriginal()


def is_org_registered(organization_id) -> bool:
    try:
        # check if organization already exists
        Organization.nodes.get(identifier=organization_id)

        return True
    except DoesNotExist:
        return False


def send_token_request_to_tp(payload, tp_url=None):
    tp_url = tp_url or config.tp_fqdn

    url = f"http://{tp_url}/api/v1/issueToken"
    resp = requests.post(url, json.dumps(payload))

    assert resp.ok, (
        f"Could not issue token, status code={resp.status_code},"
        f"content={resp.content}"
    )
    return json.loads(resp.content)


def get_provenance(organization_id, graph_id):
    d = Document.nodes.get(identifier=f"{organization_id}_{graph_id}")
    return d


def get_document_by_identifier(identifier):
    """Look up document by plain identifier (matches Java's flat document lookup)."""
    return Document.nodes.get(identifier=identifier)


def get_org_id_by_document_identifier(identifier):
    """Resolve the organization that owns a document, by querying the token's originator."""
    query = """
            MATCH (token:Token)-[:belongs_to]->(doc:Document)
            WHERE doc.identifier=$identifier
            RETURN token.originator_id
            """
    results, _ = db.cypher_query(query, {"identifier": identifier})
    if results:
        return results[0][0]
    raise DoesNotExist(f"No token found for document '{identifier}'")


def query_db_for_subgraph(
        organization_id, graph_id, requested_format, is_domain_specific
):
    suffix = "domain" if is_domain_specific else "backbone"

    d = Document.nodes.get(
        identifier=f"{graph_id}_{suffix}", format=requested_format
    )

    if not config.disable_tp:
        tokens = list(d.belongs_to.all())

        assert len(tokens) == 1, "Only one token expected per document!"
        token = tokens[0]
        t = {
            "data": {
                "originatorId": token.originator_id,
                "authorityId": token.authority_id,
                "tokenTimestamp": token.token_timestamp,
                "messageTimestamp": token.message_timestamp,
                "documentDigest": token.hash,
                "additionalData": token.additional_data,
            },
            "signature": token.signature,
        }
    else:
        t = None

    return d.graph, t


def store_subgraph_into_db(document_id, format, graph, token):
    d = Document()
    d.identifier = document_id
    d.format = format
    d.graph = graph

    if token is not None:
        (token, neo_document, trusted_party) = get_token_to_store_into_db(token, None, d)
        # change - added database transactions, not changing logic
        with db.transaction:
            d.save()
            store_token_into_db(token, neo_document, trusted_party)

    else:
        with db.transaction:
            d.save()


def get_token_to_store_into_db(token, document_id=None, neo_document=None):
    assert document_id is not None or neo_document is not None

    t = Token()
    t.signature = token["signature"]
    t.hash = token["data"]["documentDigest"]
    t.originator_id = token["data"]["originatorId"]
    t.authority_id = token["data"]["authorityId"]
    t.token_timestamp = token["data"]["tokenTimestamp"]
    t.message_timestamp = token["data"]["messageTimestamp"]
    t.additional_data = token["data"]["additionalData"]

    if neo_document is None:
        neo_document = Document.nodes.get(identifier=document_id)

    trusted_party = TrustedParty.nodes.get(identifier=token["data"]["authorityId"])

    return t, neo_document, trusted_party

# change - added function just for storing to database
def store_token_into_db(token, neo_document, trusted_party):
    token.save()
    token.belongs_to.connect(neo_document)
    token.was_issued_by.connect(trusted_party)

    return token


def get_b64_encoded_subgraph(
        organization_id, graph_id, is_domain_specific=True, format="rdf"
):
    d = Document.nodes.get(identifier=graph_id)
    prov_subgraph = retrieve_subgraph(b64decode(d.graph), d.format, is_domain_specific)
    subgraph = prov_subgraph.serialize(format=format).encode("utf-8")

    return b64encode(subgraph).decode("utf-8")


def get_token(organization_id, graph_id, document):
    registered = is_org_registered(organization_id)
    if registered:
        query = """
                MATCH (org:Organization) WHERE org.identifier=$organization_id
                MATCH (org)-[:trusts]->(tp:TrustedParty)<-[:was_issued_by]-(token:Token)-[:belongs_to]->(doc:Document)
                WHERE doc.identifier=$doc_id
                RETURN token
                """
    else:
        query = """
                MATCH (tp:DefaultTrustedParty)<-[:was_issued_by]-(token:Token)-[:belongs_to]->(doc:Document)
                WHERE doc.identifier=$doc_id
                RETURN token
                """

    results, _ = db.cypher_query(
        query,
        {"organization_id": organization_id, "doc_id": f"{organization_id}_{graph_id}"},
        resolve_objects=True,
    )

    if len(results) > 0:
        t = results[0][0]
    else:
        if registered:
            tp_url = get_tp_url_by_organization(organization_id)
        else:
            tp_url = config.tp_fqdn

        token = send_token_request_to_tp({"graph": document.graph}, tp_url)
        (token, neo_document, trusted_party) = get_token_to_store_into_db(token, None, document)
        with db.transaction:
            t = store_token_into_db(token, neo_document, trusted_party)

    token_data = {
        "originatorId": t.originator_id,
        "authorityId": t.authority_id,
        "tokenTimestamp": t.token_timestamp,
        "messageTimestamp": t.message_timestamp,
        "documentDigest": t.hash,
        "additionalData": t.additional_data,
    }
    return {"data": token_data, "signature": t.signature}


def get_b64_encoded_meta_provenance(meta_id, requested_format):
    neo_bundle = Bundle.nodes.get(identifier=meta_id)
    meta_document = convert_meta_to_prov(neo_bundle)

    g = meta_document.serialize(format=requested_format)

    return base64.b64encode(g.encode("utf-8")).decode("utf-8")


def retrieve_subgraph(graph, graph_format, is_domain_specific=True):
    # change - added calling of sub-function for traversal information or domain specific provenance retrieval
    bundle, document, records_bb, records_ds = get_backbone_and_domain(graph, graph_format, IS_BACKBONE)

    new_records = records_bb
    if is_domain_specific:
        new_records = records_ds

    new_bundle = provm.ProvBundle(
        identifier=bundle.identifier, records=new_records, namespaces=bundle.namespaces
    )
    new_doc = provm.ProvDocument(namespaces=document.namespaces)
    new_doc.add_bundle(new_bundle)

    return new_doc


def create_and_store_organization(organization_id, client_cert, intermediate_certs, tp_uri=None):
    org = Organization()
    org.identifier = organization_id
    org.client_cert = client_cert
    org.intermediate_certs = intermediate_certs

    tp, is_new_tp = get_tp(tp_uri)

    with db.transaction:
        if is_new_tp:
            tp.save()
        store_organization(org, tp)


def store_organization(organization, tp):
    organization.save()
    organization.trusts.connect(tp)

# added in https://gitlab.ics.muni.cz/422328/dbprov - not used now, left here on supervisors request
def _verify_at_remote_storage(referenced_bundle_id, referenced_meta_bundle_id):
    res_bundle = requests.head(referenced_bundle_id.uri)
    res_meta = requests.head(referenced_meta_bundle_id.uri)
    if not (res_bundle.ok and res_meta.ok):
        return False
    return True


def bundle_exists(identifier):
    return Document.nodes.get_or_none(identifier=identifier, lazy=True) is not None


def meta_bundle_exists(identifier):
    return Bundle.nodes.get_or_none(identifier=identifier, lazy=True) is not None

# added in https://gitlab.ics.muni.cz/422328/dbprov - not used now, left here on supervisors request
def _verify_at_local_storage(referenced_bundle_id, referenced_meta_bundle_id):
    organization_id = re.search(
        "(?<=/organizations/)([^/]+)", referenced_bundle_id.uri
    ).group(1)  # fix - added group(1) to extract first string found by this regex
    if not bundle_exists(f"{organization_id}_{referenced_bundle_id.localpart}"):
        return False
    if not meta_bundle_exists(referenced_meta_bundle_id.localpart):
        return False
    return True

# added in https://gitlab.ics.muni.cz/422328/dbprov - not used now, left here on supervisors request
def _referenced_bundles_exist(storage_url, connector):
    referenced_bundle_id = provm.first(
        connector.get_attribute(CPM_REFERENCED_BUNDLE_ID)
    )
    referenced_meta_bundle_id = provm.first(
        connector.get_attribute(CPM_REFERENCED_META_BUNDLE_ID)
    )
    if storage_url:
        return _verify_at_remote_storage(
            referenced_bundle_id, referenced_meta_bundle_id
        )
    return _verify_at_local_storage(referenced_bundle_id, referenced_meta_bundle_id)

# added in https://gitlab.ics.muni.cz/422328/dbprov - not used now, left here on supervisors request
def _check_referenced_bundles(connectors):
    for storage_url, connector in connectors:
        if not _referenced_bundles_exist(storage_url, connector):
            return False
    return True


# not used anywhere now - may be used in future
# added in https://gitlab.ics.muni.cz/422328/dbprov - not used now, left here on supervisors request
def check_connectors(
        forward_connectors,
        backward_connectors,
):
    return _check_referenced_bundles(forward_connectors) and _check_referenced_bundles(backward_connectors)  # fix


def modify_organization(organization_id, client_cert, intermediate_certs, tp_uri=None):
    org = Organization.nodes.get(identifier=organization_id)
    org.identifier = organization_id
    org.client_cert = client_cert
    org.intermediate_certs = intermediate_certs

    tp, is_new_tp = get_tp(tp_uri)

    # change - added transaction
    with db.transaction:
        if is_new_tp:
            tp.save()
        store_organization(org, tp)


# change - does not modify database, only returns result
def get_tp(url):
    if url is None:
        default_tp = DefaultTrustedParty.nodes.all()
        default_tp_list = list(default_tp)
        assert len(default_tp_list) == 1

        tp = TrustedParty.nodes.get(identifier=default_tp_list[0].identifier)

        return tp, False

    resp = requests.get(f"http://{url}/api/v1/info")

    assert resp.ok, "Couldn't retrieve info from TP!"
    info = json.loads(resp.content)

    try:
        tp = TrustedParty.nodes.get(identifier=info["id"])
    except DoesNotExist:
        tp = TrustedParty()
        tp.identifier = info["id"]
        tp.url = url
        tp.certificate = info["certificate"]
        return tp, True

    return tp, False


def get_tp_url_by_organization(organization_id):
    try:
        org = Organization.nodes.get(identifier=organization_id)

        trusted_parties = list(org.trusts.all())
        return trusted_parties[0].url
    except DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# New functions to match Java API
# ---------------------------------------------------------------------------

def get_token_by_document_identifier(identifier, document):
    """Get token for a document using plain identifier (no composite key).
    Matches Java: TokenService.getByDocumentIdentifier"""
    query = """
            MATCH (token:Token)-[:belongs_to]->(doc:Document)
            WHERE doc.identifier=$identifier
            RETURN token
            """
    results, _ = db.cypher_query(
        query, {"identifier": identifier}, resolve_objects=True
    )

    if len(results) > 0:
        t = results[0][0]
    else:
        tp_url = get_tp_url_by_organization(
            get_org_id_by_document_identifier(identifier)
        )
        token = send_token_request_to_tp({"graph": document.graph}, tp_url)
        (token, neo_document, trusted_party) = get_token_to_store_into_db(token, None, document)
        with db.transaction:
            t = store_token_into_db(token, neo_document, trusted_party)

    token_data = {
        "originatorId": t.originator_id,
        "authorityId": t.authority_id,
        "tokenTimestamp": t.token_timestamp,
        "messageTimestamp": t.message_timestamp,
        "documentDigest": t.hash,
        "additionalData": t.additional_data,
    }
    return {"data": token_data, "signature": t.signature}


def get_all_organizations():
    """List all organizations. Matches Java: OrganizationController.getAllOrganizations"""
    orgs = Organization.nodes.all()
    return [
        {
            "identifier": org.identifier,
            "clientCertificate": org.client_cert,
            "intermediateCertificates": org.intermediate_certs,
        }
        for org in orgs
    ]


def get_organization_detail(identifier):
    """Get single org by identifier. Matches Java: OrganizationController.getOrganizationByIdentifier"""
    try:
        org = Organization.nodes.get(identifier=identifier)
        return {
            "identifier": org.identifier,
            "clientCertificate": org.client_cert,
            "intermediateCertificates": org.intermediate_certs,
        }
    except DoesNotExist:
        return None
