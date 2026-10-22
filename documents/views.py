from datetime import date
from pathlib import Path

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy

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


def get_user_role(user):
    """Return the user's application role, defaulting to Viewer."""
    if not user.is_authenticated:
        return None

    profile = getattr(user, "profile", None)

    if profile is None:
        return UserProfile.VIEWER

    return profile.role


def can_upload_documents(user):
    """Only Administrators and Owners can upload documents."""
    return get_user_role(user) in {
        UserProfile.ADMINISTRATOR,
        UserProfile.OWNER,
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
    role = get_user_role(request.user)

    # Handle document uploads.
    if request.method == "POST":
        if not can_upload_documents(request.user):
            AuditLog.objects.create(
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

        elif len(title) > 200:
            messages.error(
                request,
                "The title must not exceed 200 characters.",
            )

        elif not category or len(category) > 100:
            messages.error(
                request,
                "Category must contain 1–100 characters.",
            )

        elif uploaded_file.size > MAX_FILE_SIZE:
            messages.error(
                request,
                "File size must not exceed 5 MB.",
            )

        elif Path(uploaded_file.name).suffix.lower() not in ALLOWED_EXTENSIONS:
            messages.error(
                request,
                "Invalid file type. Upload PDF, TXT, PNG, JPG, or JPEG.",
            )

        else:
            document = Document.objects.create(
                title=title,
                category=category,
                file=uploaded_file,
                owner=request.user,
            )

            AuditLog.objects.create(
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

    # Show only documents owned by the logged-in user.
    documents = Document.objects.filter(
        owner=request.user,
    ).order_by("-uploaded_at")

    # Read search filters.
    search_query = request.GET.get("q", "").strip()
    owner_query = request.GET.get("owner", "").strip()
    category_query = request.GET.get("category", "").strip()
    upload_date = request.GET.get("uploaded_date", "").strip()

    # Filter by document title.
    if search_query:
        documents = documents.filter(
            title__icontains=search_query,
        )

    # Filter by owner username.
    if owner_query:
        documents = documents.filter(
            owner__username__icontains=owner_query,
        )

    # Filter by category.
    if category_query:
        documents = documents.filter(
            category__icontains=category_query,
        )

    # Filter by upload date.
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

    # Display documents shared with the logged-in user.
    shared_accesses = DocumentAccess.objects.filter(
        user=request.user,
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
    """
    Allow the owner or a user with explicit EDIT permission
    to update a document's title and category.
    """
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
        AuditLog.objects.create(
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
                "Title must contain 1–200 characters.",
            )

        elif not category or len(category) > 100:
            messages.error(
                request,
                "Category must contain 1–100 characters.",
            )

        else:
            document.title = title
            document.category = category

            document.save(
                update_fields=["title", "category"],
            )

            AuditLog.objects.create(
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
        AuditLog.objects.create(
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
        AuditLog.objects.create(
            user=request.user,
            document=document,
            action="document_download",
            result=AuditLog.DENIED,
            details="Download failed: file unavailable.",
        )

        raise Http404("Document file is unavailable.")

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
    # Only the document owner can share it.
    document = get_object_or_404(
        Document,
        id=document_id,
        owner=request.user,
    )

    if request.method != "POST":
        return redirect("dashboard")

    username = request.POST.get("username", "").strip()
    permission = request.POST.get("permission", "").strip()

    if not username:
        messages.error(
            request,
            "Please enter a username.",
        )
        return redirect("dashboard")

    if permission not in [
        DocumentAccess.READ,
        DocumentAccess.EDIT,
    ]:
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

    DocumentAccess.objects.update_or_create(
        document=document,
        user=shared_user,
        defaults={
            "permission": permission,
        },
    )

    AuditLog.objects.create(
        user=request.user,
        document=document,
        action="document_share",
        result=AuditLog.SUCCESS,
        details=f"Shared with {shared_user.username}: {permission}",
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


@login_required
def admin_activity_dashboard(request):
    # Only application Administrators can access this page.
    if get_user_role(request.user) != UserProfile.ADMINISTRATOR:
        raise Http404("Page not found")

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