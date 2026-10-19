from django.contrib import admin
from .models import Document, DocumentAccess, AuditLog


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ("title", "owner", "uploaded_at")
    search_fields = ("title", "owner__username")
    list_filter = ("uploaded_at",)


@admin.register(DocumentAccess)
class DocumentAccessAdmin(admin.ModelAdmin):
    list_display = ("document", "user", "permission", "granted_at")
    search_fields = ("document__title", "user__username")
    list_filter = ("permission", "granted_at")


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