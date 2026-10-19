from pathlib import Path

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy

from .models import Document, DocumentAccess, AuditLog


User = get_user_model()

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
}


def home(request):
    return render(request, "documents/home.html")


class TrustVaultLoginView(LoginView):
    template_name = "documents/login.html"
    redirect_authenticated_user = True


class TrustVaultLogoutView(LogoutView):
    next_page = reverse_lazy("home")

@login_required
def dashboard(request):
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        uploaded_file = request.FILES.get("file")

        if not title or not uploaded_file:
            messages.error(
                request,
                "Please enter a title and choose a file."
            )

        elif len(title) > 200:
            messages.error(
                request,
                "The title must not exceed 200 characters."
            )

        elif uploaded_file.size > MAX_FILE_SIZE:
            messages.error(
                request,
                "File size must not exceed 5 MB."
            )

        elif (
            Path(uploaded_file.name).suffix.lower()
            not in ALLOWED_EXTENSIONS
        ):
            messages.error(
                request,
                "Invalid file type. Upload PDF, TXT, PNG, JPG, or JPEG."
            )

        else:
            Document.objects.create(
                title=title,
                file=uploaded_file,
                owner=request.user,
            )

            messages.success(
                request,
                "Document uploaded successfully!"
            )

            return redirect("dashboard")

    # Documents owned by the logged-in user
    documents = Document.objects.filter(
        owner=request.user
    ).order_by("-uploaded_at")

    # Documents shared with the logged-in user
    shared_accesses = DocumentAccess.objects.filter(
        user=request.user
    ).select_related(
        "document",
        "document__owner",
    ).order_by("-document__uploaded_at")

    return render(
        request,
        "documents/dashboard.html",
        {
            "documents": documents,
            "shared_accesses": shared_accesses,
        },
    )


@login_required
def download_document(request, document_id):
    document = get_object_or_404(
        Document,
        id=document_id,
    )

    # Check whether the user owns the document.
    is_owner = document.owner_id == request.user.id

    # Check whether the document has been shared with the user.
    has_access = DocumentAccess.objects.filter(
        document=document,
        user=request.user,
        permission__in=[
            DocumentAccess.READ,
            DocumentAccess.EDIT,
        ],
    ).exists()

    # Record denied access attempts.
    if not is_owner and not has_access:
        AuditLog.objects.create(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.DENIED,
            details="Download denied: no permission.",
        )

        raise Http404("Document not found.")

    # Open the file.
    try:
        document.file.open("rb")

    except (FileNotFoundError, OSError, ValueError):
        AuditLog.objects.create(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.DENIED,
            details="Download failed: file unavailable.",
        )

        raise Http404("Document file is unavailable.")

    # Record the successful authorization and file opening.
    AuditLog.objects.create(
        user=request.user,
        document=document,
        action="document_download",
        result=AuditLog.SUCCESS,
        details="Download authorized and file opened.",
    )

    return FileResponse(
        document.file,
        as_attachment=True,
        filename=Path(document.file.name).name,
    )


@login_required
def share_document(request, document_id):
    # Only the document owner can share the document.
    document = get_object_or_404(
        Document,
        id=document_id,
        owner=request.user,
    )

    # Sharing must use a POST request.
    if request.method != "POST":
        return redirect("dashboard")

    username = request.POST.get("username", "").strip()
    permission = request.POST.get("permission", "").strip()

    # Validate the username.
    if not username:
        messages.error(
            request,
            "Please enter a username."
        )
        return redirect("dashboard")

    # Validate the selected permission.
    if permission not in [
        DocumentAccess.READ,
        DocumentAccess.EDIT,
    ]:
        messages.error(
            request,
            "Invalid permission selected."
        )
        return redirect("dashboard")

    # Find the user who will receive access.
    try:
        shared_user = User.objects.get(
            username=username,
        )

    except User.DoesNotExist:
        messages.error(
            request,
            "User not found."
        )
        return redirect("dashboard")

    # Prevent sharing with yourself.
    if shared_user == request.user:
        messages.error(
            request,
            "You cannot share a document with yourself."
        )
        return redirect("dashboard")

    # Create access or update existing access.
    DocumentAccess.objects.update_or_create(
        document=document,
        user=shared_user,
        defaults={
            "permission": permission,
        },
    )

    # Record the sharing activity in the audit log.
    AuditLog.objects.create(
        user=request.user,
        document=document,
        action="document_share",
        result=AuditLog.SUCCESS,
        details=(
            f"Shared with {shared_user.username}: "
            f"{permission}"
        ),
    )

    messages.success(
        request,
        f"Document shared with {shared_user.username}.",
    )

    return redirect("dashboard")

@login_required
def revoke_document_access(request, document_id, access_id):
    if request.method != "POST":
        return redirect("dashboard")

    document = get_object_or_404(
        Document,
        id=document_id,
        owner=request.user,
    )

    access = get_object_or_404(
        DocumentAccess,
        id=access_id,
        document=document,
    )

    recipient_username = access.user.username

    access.delete()

    AuditLog.objects.create(
        user=request.user,
        document=document,
        action="document_access_revoked",
        result=AuditLog.SUCCESS,
        details=f"Access revoked for {recipient_username}",
    )

    messages.success(
        request,
        f"Access revoked for {recipient_username}.",
    )

    return redirect("dashboard")