from django.urls import path

from . import views

urlpatterns = [
    # Organization endpoints (matches Java: OrganizationController)
    path("organizations", views.organizations, name="organizations"),
    path("organizations/<identifier>", views.organization_detail, name="organization_detail"),

    # Document endpoints (matches Java: DocumentController)
    path("documents", views.documents_create, name="documents_create"),
    path("documents/<identifier>", views.document_by_id, name="document_by_id"),
    path("documents/<identifier>/domain-specific", views.document_domain_specific, name="domain_specific"),
    path("documents/<identifier>/backbone", views.document_backbone, name="backbone"),

    # Meta document endpoint (matches Java: MetaDocumentController - HEAD only)
    path("documents/meta/<uuid>", views.meta_document, name="meta_document"),
]
