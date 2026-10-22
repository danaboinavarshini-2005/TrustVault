from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ADMINISTRATOR = "administrator"
    OWNER = "owner"
    VIEWER = "viewer"

    ROLE_CHOICES = [
        (ADMINISTRATOR, "Administrator"),
        (OWNER, "Owner"),
        (VIEWER, "Viewer"),
    ]

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile",
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=VIEWER,
    )

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"


class Document(models.Model):
    title = models.CharField(max_length=200)

    category = models.CharField(
        max_length=100,
        default="General",
        db_index=True,
    )

    file = models.FileField(
        upload_to="documents/",
    )

    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="documents",
    )

    uploaded_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    def __str__(self):
        return self.title


class DocumentAccess(models.Model):
    READ = "read"
    EDIT = "edit"

    PERMISSION_CHOICES = [
        (READ, "Read"),
        (EDIT, "Edit"),
    ]

    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="access_permissions",
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="document_permissions",
    )

    permission = models.CharField(
        max_length=10,
        choices=PERMISSION_CHOICES,
        default=READ,
    )

    granted_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["document", "user"],
                name="unique_document_user_access",
            )
        ]

    def __str__(self):
        return (
            f"{self.user.username} - "
            f"{self.document.title} ({self.permission})"
        )


class AuditLog(models.Model):
    SUCCESS = "success"
    DENIED = "denied"

    RESULT_CHOICES = [
        (SUCCESS, "Success"),
        (DENIED, "Denied"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    document = models.ForeignKey(
        Document,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    action = models.CharField(
        max_length=50,
    )

    result = models.CharField(
        max_length=10,
        choices=RESULT_CHOICES,
    )

    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    details = models.CharField(
        max_length=255,
        blank=True,
    )

    def __str__(self):
        return f"{self.action} - {self.result} - {self.timestamp}"