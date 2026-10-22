
from django.contrib import admin
from django.urls import path
from documents import views


urlpatterns = [
    path("admin/", admin.site.urls),

    path("", views.home, name="home"),

    path(
        "login/",
        views.TrustVaultLoginView.as_view(),
        name="login",
    ),

    path(
        "register/",
        views.register,
        name="register",
    ),

    path(
        "logout/",
        views.TrustVaultLogoutView.as_view(),
        name="logout",
    ),

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard",
    ),

    path(
        "admin-activity/",
        views.admin_activity_dashboard,
        name="admin_activity_dashboard",
    ),

    path(
        "documents/<int:document_id>/download/",
        views.download_document,
        name="download_document",
    ),

    path(
        "documents/<int:document_id>/share/",
        views.share_document,
        name="share_document",
    ),

    path(
        "documents/<int:document_id>/revoke/<int:access_id>/",
        views.revoke_document_access,
        name="revoke_document_access",
    ),

    path(
        "documents/<int:document_id>/edit/",
        views.edit_document,
        name="edit_document",
    ),
]

