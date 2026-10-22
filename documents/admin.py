from django.contrib import admin

from .models import (
    Document,
    DocumentAccess,
    AuditLog,
    UserProfile,
)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role")
    search_fields = ("user__username", "user__email")
    list_filter = ("role",)
    ordering = ("user__username",)


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ("title", "owner", "uploaded_at")
    search_fields = ("title", "owner__username")
    list_filter = ("uploaded_at",)
    ordering = ("-uploaded_at",)


@admin.register(DocumentAccess)
class DocumentAccessAdmin(admin.ModelAdmin):
    list_display = (
        "document",
        "user",
        "permission",
        "granted_at",
    )

    search_fields = (
        "document__title",
        "user__username",
    )

    list_filter = ("permission", "granted_at")
    ordering = ("-granted_at",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "action",
        "user",
        "document",
        "result",
        "timestamp",
    )

    search_fields = (
        "action",
        "user__username",
        "document__title",
        "details",
    )

    list_filter = ("result", "action", "timestamp")
    ordering = ("-timestamp",)

    # Audit records cannot be edited through Django Admin.
    readonly_fields = (
        "user",
        "document",
        "action",
        "result",
        "timestamp",
        "details",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False