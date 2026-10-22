
from datetime import date
from pathlib import Path

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView, LogoutView
from django.db import transaction
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.views.decorators.http import require_POST

from .models import Document, DocumentAccess, AuditLog, UserProfile


User = get_user_model()

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
}

ALLOWED_CONTENT_TYPES = {
    ".pdf": {"application/pdf", "application/octet-stream"},
    ".txt": {"text/plain", "application/octet-stream"},
    ".png": {"image/png", "application/octet-stream"},
    ".jpg": {"image/jpeg", "application/octet-stream"},
    ".jpeg": {"image/jpeg", "application/octet-stream"},
}


def get_user_role(user):
    """Return the user's role, defaulting to Viewer."""
    if not user.is_authenticated:
        return None

    try:
        return user.profile.role
    except UserProfile.DoesNotExist:
        return UserProfile.VIEWER


def can_upload_documents(user):
    """Only Administrators and Owners can upload documents."""
    return (
        user.is_authenticated
        and get_user_role(user) in {
            UserProfile.ADMINISTRATOR,
            UserProfile.OWNER,
        }
    )


def log_audit(user, action, result, document=None, details=""):
    """Create an audit record."""
    AuditLog.objects.create(
        user=user,
        document=document,
        action=action,
        result=result,
        details=details,
    )


def home(request):
    """Display the TrustVault home page."""
    return render(request, "documents/home.html")


def register(request):
    """
    Register a new user with the default Viewer role.
    Existing authenticated users are redirected to the dashboard.
    """
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = UserCreationForm(request.POST)

        if form.is_valid():
            with transaction.atomic():
                user = form.save()

                UserProfile.objects.get_or_create(
                    user=user,
                    defaults={
                        "role": UserProfile.VIEWER,
                    },
                )

            messages.success(
                request,
                "Your account was created successfully. Please log in.",
            )

            return redirect("login")

    else:
        form = UserCreationForm()

    return render(
        request,
        "documents/register.html",
        {
            "form": form,
        },
    )


class TrustVaultLoginView(LoginView):
    """Display the login page."""
    template_name = "documents/login.html"
    redirect_authenticated_user = True


class TrustVaultLogoutView(LogoutView):
    """Log out the current user."""
    next_page = reverse_lazy("home")


@login_required
def dashboard(request):
    """Display documents, shared documents, and upload functionality."""
    role = get_user_role(request.user)

    # Handle document uploads.
    if request.method == "POST":
        if not can_upload_documents(request.user):
            log_audit(
                user=request.user,
                action="document_upload",
                result=AuditLog.DENIED,
                details="Upload denied: insufficient role.",
            )

            messages.error(
                request,
                "Your role does not permit document uploads.",
            )
            return redirect("dashboard")

        title = request.POST.get("title", "").strip()
        category = request.POST.get("category", "General").strip()
        uploaded_file = request.FILES.get("file")

        if not title or not uploaded_file:
            messages.error(
                request,
                "Please enter a title and choose a file.",
            )
            return redirect("dashboard")

        if len(title) > 200:
            messages.error(
                request,
                "The title must not exceed 200 characters.",
            )
            return redirect("dashboard")

        if not category or len(category) > 100:
            messages.error(
                request,
                "Category must contain 1-100 characters.",
            )
            return redirect("dashboard")

        extension = Path(uploaded_file.name).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            messages.error(
                request,
                "Invalid file type. Upload PDF, TXT, PNG, JPG, or JPEG.",
            )
            return redirect("dashboard")

        if uploaded_file.size <= 0:
            messages.error(
                request,
                "The uploaded file is empty.",
            )
            return redirect("dashboard")

        if uploaded_file.size > MAX_FILE_SIZE:
            messages.error(
                request,
                "File size must not exceed 5 MB.",
            )
            return redirect("dashboard")

        content_type = (
            getattr(uploaded_file, "content_type", "") or ""
        ).lower()

        if content_type not in ALLOWED_CONTENT_TYPES[extension]:
            messages.error(
                request,
                "The uploaded file type does not match the extension.",
            )
            return redirect("dashboard")

        document = Document.objects.create(
            title=title,
            category=category,
            file=uploaded_file,
            owner=request.user,
        )

        log_audit(
            user=request.user,
            document=document,
            action="document_upload",
            result=AuditLog.SUCCESS,
            details="Document uploaded successfully.",
        )

        messages.success(
            request,
            "Document uploaded successfully!",
        )
        return redirect("dashboard")

    # Display documents owned by the current user.
    documents = Document.objects.filter(
        owner=request.user,
    ).order_by("-uploaded_at")

    # Read search filters.
    search_query = request.GET.get("q", "").strip()
    owner_query = request.GET.get("owner", "").strip()
    category_query = request.GET.get("category", "").strip()
    upload_date = request.GET.get("uploaded_date", "").strip()

    if search_query:
        documents = documents.filter(
            title__icontains=search_query,
        )

    if owner_query:
        documents = documents.filter(
            owner__username__icontains=owner_query,
        )

    if category_query:
        documents = documents.filter(
            category__icontains=category_query,
        )

    if upload_date:
        try:
            parsed_date = date.fromisoformat(upload_date)

            documents = documents.filter(
                uploaded_at__date=parsed_date,
            )

        except ValueError:
            messages.error(
                request,
                "Please enter a valid upload date.",
            )
            upload_date = ""

    # Documents shared with the current user.
    shared_accesses = DocumentAccess.objects.filter(
        user=request.user,
        permission__in=[
            DocumentAccess.READ,
            DocumentAccess.EDIT,
        ],
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
            "search_query": search_query,
            "owner_query": owner_query,
            "category_query": category_query,
            "upload_date": upload_date,
            "user_role": role,
            "can_upload": can_upload_documents(request.user),
        },
    )


@login_required
def edit_document(request, document_id):
    """Allow owners and users with EDIT permission to edit metadata."""
    document = get_object_or_404(
        Document,
        id=document_id,
    )

    is_owner = document.owner_id == request.user.id

    has_edit_access = DocumentAccess.objects.filter(
        document=document,
        user=request.user,
        permission=DocumentAccess.EDIT,
    ).exists()

    if not is_owner and not has_edit_access:
        log_audit(
            user=request.user,
            document=document,
            action="document_edit",
            result=AuditLog.DENIED,
            details="Edit denied: insufficient permission.",
        )
        raise Http404("Document not found.")

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        category = request.POST.get("category", "").strip()

        if not title or len(title) > 200:
            messages.error(
                request,
                "Title must contain 1-200 characters.",
            )

        elif not category or len(category) > 100:
            messages.error(
                request,
                "Category must contain 1-100 characters.",
            )

        else:
            document.title = title
            document.category = category

            document.save(
                update_fields=["title", "category"],
            )

            log_audit(
                user=request.user,
                document=document,
                action="document_edit",
                result=AuditLog.SUCCESS,
                details="Document title/category updated.",
            )

            messages.success(
                request,
                "Document updated successfully!",
            )
            return redirect("dashboard")

    return render(
        request,
        "documents/edit_document.html",
        {
            "document": document,
        },
    )


@login_required
def download_document(request, document_id):
    """Allow owners and authorized users to download documents."""
    document = get_object_or_404(
        Document,
        id=document_id,
    )

    is_owner = document.owner_id == request.user.id

    has_access = DocumentAccess.objects.filter(
        document=document,
        user=request.user,
        permission__in=[
            DocumentAccess.READ,
            DocumentAccess.EDIT,
        ],
    ).exists()

    if not is_owner and not has_access:
        log_audit(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.DENIED,
            details="Download denied: no permission.",
        )
        raise Http404("Document not found.")

    try:
        document.file.open("rb")

    except (FileNotFoundError, OSError, ValueError):
        log_audit(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.DENIED,
            details="Download failed: file unavailable.",
        )
        raise Http404("Document file is unavailable.")

    try:
        log_audit(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.SUCCESS,
            details="Download authorized and file opened.",
        )

    except Exception:
        document.file.close()
        raise

    return FileResponse(
        document.file,
        as_attachment=True,
        filename=Path(document.file.name).name,
    )


@login_required
@require_POST
def share_document(request, document_id):
    """Only the document owner can share it."""
    document = get_object_or_404(
        Document,
        id=document_id,
        owner=request.user,
    )

    username = request.POST.get("username", "").strip()
    permission = request.POST.get("permission", "").strip()

    if not username:
        messages.error(
            request,
            "Please enter a username.",
        )
        return redirect("dashboard")

    if permission not in {
        DocumentAccess.READ,
        DocumentAccess.EDIT,
    }:
        messages.error(
            request,
            "Invalid permission selected.",
        )
        return redirect("dashboard")

    try:
        shared_user = User.objects.get(
            username=username,
        )

    except User.DoesNotExist:
        messages.error(
            request,
            "User not found.",
        )
        return redirect("dashboard")

    if shared_user == request.user:
        messages.error(
            request,
            "You cannot share a document with yourself.",
        )
        return redirect("dashboard")

    access, created = DocumentAccess.objects.update_or_create(
        document=document,
        user=shared_user,
        defaults={
            "permission": permission,
        },
    )

    details = (
        f"Shared with {shared_user.username}: {permission}"
        if created
        else f"Updated access for {shared_user.username}: {permission}"
    )

    log_audit(
        user=request.user,
        document=document,
        action="document_share",
        result=AuditLog.SUCCESS,
        details=details,
    )

    messages.success(
        request,
        f"Document shared with {shared_user.username}.",
    )
    return redirect("dashboard")


@login_required
@require_POST
def revoke_document_access(request, document_id, access_id):
    """Only the document owner can revoke access."""
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

    log_audit(
        user=request.user,
        document=document,
        action="document_access_revoked",
        result=AuditLog.SUCCESS,
        details=f"Access revoked for {recipient_username}",
    )

    access.delete()

    messages.success(
        request,
        f"Access revoked for {recipient_username}.",
    )
    return redirect("dashboard")


@login_required
def admin_activity_dashboard(request):
    """Only Administrators can view audit logs."""
    if get_user_role(request.user) != UserProfile.ADMINISTRATOR:
        raise Http404("Page not found.")

    logs = AuditLog.objects.select_related(
        "user",
        "document",
    ).order_by("-timestamp")

    return render(
        request,
        "documents/admin_activity.html",
        {
            "logs": logs,
        },
    )

