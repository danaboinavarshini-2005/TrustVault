from django.test import TestCase
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from .models import Document, AuditLog

class DocumentSecurityTests(TestCase):

 def setUp(self):
    # Create the document owner.
    self.owner = User.objects.create_user(
        username="owner",
        password="TestPass123!"
    )

    # Create another user without permission.
    self.other_user = User.objects.create_user(
        username="otheruser",
        password="TestPass123!"
    )

    # Create a test document.
    uploaded_file = SimpleUploadedFile(
        "test.txt",
        b"This is a TrustVault test document.",
        content_type="text/plain"
    )

    self.document = Document.objects.create(
        title="Test Document",
        file=uploaded_file,
        owner=self.owner
    )

    self.download_url = reverse(
        "download_document",
        args=[self.document.id]
    )

 def test_owner_can_download_document(self):
    # Log in as the owner.
    self.client.login(
        username="owner",
        password="TestPass123!"
    )

    response = self.client.get(self.download_url)

    self.assertEqual(response.status_code, 200)

    self.assertTrue(
        AuditLog.objects.filter(
            user=self.owner,
            document=self.document,
            action="document_download",
            result=AuditLog.SUCCESS
        ).exists()
    )

 def test_unauthorized_user_cannot_download_document(self):
    # Log in as a user without document permission.
    self.client.login(
        username="otheruser",
        password="TestPass123!"
    )

    response = self.client.get(self.download_url)

    self.assertEqual(response.status_code, 404)

    self.assertTrue(
        AuditLog.objects.filter(
            user=self.other_user,
            document=self.document,
            action="document_download",
            result=AuditLog.DENIED
        ).exists()
    )