from django.test import TestCase
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from .models import Document, DocumentAccess, AuditLog, UserProfile


class DocumentSecurityTests(TestCase):

    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.owner,
            role=UserProfile.OWNER,
        )

        self.other_user = User.objects.create_user(
            username="otheruser",
            password="TestPass123!",
        )

        uploaded_file = SimpleUploadedFile(
            "test.txt",
            b"This is a TrustVault test document.",
            content_type="text/plain",
        )

        self.document = Document.objects.create(
            title="Test Document",
            file=uploaded_file,
            owner=self.owner,
        )

        self.download_url = reverse(
            "download_document",
            args=[self.document.id],
        )

    def test_owner_can_download_document(self):
        self.client.login(
            username="owner",
            password="TestPass123!",
        )

        response = self.client.get(self.download_url)

        self.assertEqual(response.status_code, 200)

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                document=self.document,
                action="document_download",
                result=AuditLog.SUCCESS,
            ).exists()
        )

    def test_unauthorized_user_cannot_download_document(self):
        self.client.login(
            username="otheruser",
            password="TestPass123!",
        )

        response = self.client.get(self.download_url)

        self.assertEqual(response.status_code, 404)

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.other_user,
                document=self.document,
                action="document_download",
                result=AuditLog.DENIED,
            ).exists()
        )

    def test_authorized_user_can_download_shared_document(self):
        viewer = User.objects.create_user(
            username="viewer",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=viewer,
            role=UserProfile.VIEWER,
        )

        DocumentAccess.objects.create(
            document=self.document,
            user=viewer,
            permission=DocumentAccess.READ,
        )

        self.client.login(
            username="viewer",
            password="TestPass123!",
        )

        response = self.client.get(self.download_url)

        self.assertEqual(response.status_code, 200)

        self.assertTrue(
            AuditLog.objects.filter(
                user=viewer,
                document=self.document,
                action="document_download",
                result=AuditLog.SUCCESS,
            ).exists()
        )

    def test_revoked_access_blocks_download(self):
        viewer = User.objects.create_user(
            username="viewer",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=viewer,
            role=UserProfile.VIEWER,
        )

        access = DocumentAccess.objects.create(
            document=self.document,
            user=viewer,
            permission=DocumentAccess.READ,
        )

        self.client.login(
            username="owner",
            password="TestPass123!",
        )

        revoke_url = reverse(
            "revoke_document_access",
            args=[self.document.id, access.id],
        )

        revoke_response = self.client.post(revoke_url)

        self.assertEqual(revoke_response.status_code, 302)

        self.assertFalse(
            DocumentAccess.objects.filter(
                document=self.document,
                user=viewer,
            ).exists()
        )

        self.client.logout()

        self.client.login(
            username="viewer",
            password="TestPass123!",
        )

        download_response = self.client.get(self.download_url)

        self.assertEqual(download_response.status_code, 404)

    def test_non_owner_cannot_share_document(self):
        self.client.login(
            username="otheruser",
            password="TestPass123!",
        )

        share_url = reverse(
            "share_document",
            args=[self.document.id],
        )

        response = self.client.post(
            share_url,
            {
                "username": "viewer",
                "permission": DocumentAccess.READ,
            },
        )

        self.assertEqual(response.status_code, 404)

        self.assertFalse(
            DocumentAccess.objects.filter(
                document=self.document,
                user__username="viewer",
            ).exists()
        )

    def test_non_owner_cannot_revoke_access(self):
        viewer = User.objects.create_user(
            username="viewer",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=viewer,
            role=UserProfile.VIEWER,
        )

        access = DocumentAccess.objects.create(
            document=self.document,
            user=viewer,
            permission=DocumentAccess.READ,
        )

        self.client.login(
            username="otheruser",
            password="TestPass123!",
        )

        revoke_url = reverse(
            "revoke_document_access",
            args=[self.document.id, access.id],
        )

        response = self.client.post(revoke_url)

        self.assertEqual(response.status_code, 404)

        self.assertTrue(
            DocumentAccess.objects.filter(
                id=access.id,
            ).exists()
        )

    def test_document_upload_creates_audit_log(self):
        self.client.login(
            username="owner",
            password="TestPass123!",
        )

        uploaded_file = SimpleUploadedFile(
            "new_test.txt",
            b"This is a new test document.",
            content_type="text/plain",
        )

        response = self.client.post(
            reverse("dashboard"),
            {
                "title": "New Test Document",
                "file": uploaded_file,
            },
        )

        self.assertEqual(response.status_code, 302)

        document = Document.objects.get(
            title="New Test Document",
            owner=self.owner,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                document=document,
                action="document_upload",
                result=AuditLog.SUCCESS,
            ).exists()
        )

    def test_viewer_cannot_upload_document(self):
        viewer = User.objects.create_user(
            username="viewer",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=viewer,
            role=UserProfile.VIEWER,
        )

        self.client.login(
            username="viewer",
            password="TestPass123!",
        )

        uploaded_file = SimpleUploadedFile(
            "viewer_test.txt",
            b"Viewer upload attempt.",
            content_type="text/plain",
        )

        response = self.client.post(
            reverse("dashboard"),
            {
                "title": "Viewer Test Document",
                "file": uploaded_file,
            },
        )

        self.assertEqual(response.status_code, 302)

        self.assertFalse(
            Document.objects.filter(
                title="Viewer Test Document",
                owner=viewer,
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=viewer,
                action="document_upload",
                result=AuditLog.DENIED,
            ).exists()
        )


class AdminActivityDashboardTests(TestCase):

    def setUp(self):
        self.admin = User.objects.create_user(
            username="activity_admin",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.admin,
            role=UserProfile.ADMINISTRATOR,
        )

        self.owner = User.objects.create_user(
            username="activity_owner",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.owner,
            role=UserProfile.OWNER,
        )

        self.viewer = User.objects.create_user(
            username="activity_viewer",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.viewer,
            role=UserProfile.VIEWER,
        )

        self.url = reverse("admin_activity_dashboard")

    def test_administrator_can_open_activity_dashboard(self):
        self.client.login(
            username="activity_admin",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)

        self.assertTemplateUsed(
            response,
            "documents/admin_activity.html",
        )

    def test_owner_cannot_open_activity_dashboard(self):
        self.client.login(
            username="activity_owner",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 404)

    def test_viewer_cannot_open_activity_dashboard(self):
        self.client.login(
            username="activity_viewer",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 404)

    def test_logged_out_user_is_redirected_to_login(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)

        self.assertIn(
            reverse("login"),
            response.url,
        )

    def test_activity_dashboard_displays_audit_events(self):
        AuditLog.objects.create(
            user=self.owner,
            document=None,
            action="document_upload",
            result=AuditLog.SUCCESS,
            details="Dashboard test event",
        )

        self.client.login(
            username="activity_admin",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard test event")
        self.assertContains(response, "activity_owner")
        self.assertContains(response, "document_upload")


class DocumentEditSecurityTests(TestCase):

    def setUp(self):
        self.owner = User.objects.create_user(
            username="edit_owner",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.owner,
            role=UserProfile.OWNER,
        )

        self.editor = User.objects.create_user(
            username="edit_editor",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.editor,
            role=UserProfile.VIEWER,
        )

        self.reader = User.objects.create_user(
            username="edit_reader",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.reader,
            role=UserProfile.VIEWER,
        )

        self.outsider = User.objects.create_user(
            username="edit_outsider",
            password="TestPass123!",
        )

        UserProfile.objects.create(
            user=self.outsider,
            role=UserProfile.VIEWER,
        )

        uploaded_file = SimpleUploadedFile(
            "edit_test.txt",
            b"TrustVault edit security test.",
            content_type="text/plain",
        )

        self.document = Document.objects.create(
            title="Original Title",
            category="General",
            file=uploaded_file,
            owner=self.owner,
        )

        self.editor_access = DocumentAccess.objects.create(
            document=self.document,
            user=self.editor,
            permission=DocumentAccess.EDIT,
        )

        DocumentAccess.objects.create(
            document=self.document,
            user=self.reader,
            permission=DocumentAccess.READ,
        )

        self.edit_url = reverse(
            "edit_document",
            args=[self.document.id],
        )

    def test_owner_can_open_edit_page(self):
        self.client.login(
            username="edit_owner",
            password="TestPass123!",
        )

        response = self.client.get(self.edit_url)

        self.assertEqual(response.status_code, 200)

    def test_owner_can_update_document(self):
        self.client.login(
            username="edit_owner",
            password="TestPass123!",
        )

        response = self.client.post(
            self.edit_url,
            {
                "title": "Owner Updated Title",
                "category": "Reports",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.document.refresh_from_db()

        self.assertEqual(self.document.title, "Owner Updated Title")
        self.assertEqual(self.document.category, "Reports")

    def test_user_with_edit_permission_can_update_document(self):
        self.client.login(
            username="edit_editor",
            password="TestPass123!",
        )

        response = self.client.post(
            self.edit_url,
            {
                "title": "Editor Updated Title",
                "category": "Shared Reports",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.document.refresh_from_db()

        self.assertEqual(self.document.title, "Editor Updated Title")
        self.assertEqual(self.document.category, "Shared Reports")

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.editor,
                document=self.document,
                action="document_edit",
                result=AuditLog.SUCCESS,
            ).exists()
        )

    def test_read_only_user_cannot_open_edit_page(self):
        self.client.login(
            username="edit_reader",
            password="TestPass123!",
        )

        response = self.client.get(self.edit_url)

        self.assertEqual(response.status_code, 404)

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.reader,
                document=self.document,
                action="document_edit",
                result=AuditLog.DENIED,
            ).exists()
        )

    def test_read_only_user_cannot_update_document(self):
        self.client.login(
            username="edit_reader",
            password="TestPass123!",
        )

        response = self.client.post(
            self.edit_url,
            {
                "title": "Unauthorized Change",
                "category": "Unauthorized",
            },
        )

        self.assertEqual(response.status_code, 404)

        self.document.refresh_from_db()

        self.assertEqual(self.document.title, "Original Title")
        self.assertEqual(self.document.category, "General")

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.reader,
                document=self.document,
                action="document_edit",
                result=AuditLog.DENIED,
            ).exists()
        )

    def test_user_without_access_cannot_edit_document(self):
        self.client.login(
            username="edit_outsider",
            password="TestPass123!",
        )

        response = self.client.get(self.edit_url)

        self.assertEqual(response.status_code, 404)

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.outsider,
                document=self.document,
                action="document_edit",
                result=AuditLog.DENIED,
            ).exists()
        )

    def test_revoked_edit_permission_blocks_future_edits(self):
        self.client.login(
            username="edit_owner",
            password="TestPass123!",
        )

        revoke_url = reverse(
            "revoke_document_access",
            args=[self.document.id, self.editor_access.id],
        )

        revoke_response = self.client.post(revoke_url)

        self.assertEqual(revoke_response.status_code, 302)

        self.assertFalse(
            DocumentAccess.objects.filter(
                document=self.document,
                user=self.editor,
            ).exists()
        )

        self.client.logout()

        self.client.login(
            username="edit_editor",
            password="TestPass123!",
        )

        response = self.client.post(
            self.edit_url,
            {
                "title": "Change After Revocation",
                "category": "Unauthorized",
            },
        )

        self.assertEqual(response.status_code, 404)

        self.document.refresh_from_db()

        self.assertEqual(self.document.title, "Original Title")

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.editor,
                document=self.document,
                action="document_edit",
                result=AuditLog.DENIED,
            ).exists()
        )