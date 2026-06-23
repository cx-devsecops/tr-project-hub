"""
Comprehensive tests for Flask application and Werkzeug CVE-2023-46136 remediation.

This test suite validates:
1. Flask 2.3.3 and Werkzeug 3.0.1 compatibility
2. Request context handling with Flask 2.x API changes
3. Protection against multipart data DoS attacks (CVE-2023-46136)
4. Application endpoints functionality
"""

import pytest
import io
from backend.app import app


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def app_context():
    """Create an application context for testing."""
    with app.app_context():
        yield


class TestFlaskCompatibility:
    """Tests for Flask 2.3.3 compatibility and request context handling."""

    def test_request_context_initialization(self, client):
        """Test that request context is properly initialized using Flask 2.x API."""
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

    def test_has_request_context_in_before_request(self, client):
        """
        Test that has_request_context() works properly in before_request hook.
        This validates the fix for the deprecated _request_ctx_stack.
        """
        response = client.get('/')
        assert response.status_code == 200
        data = response.get_json()
        assert 'message' in data
        assert data['message'] == 'ProjectHub API'

    def test_error_handlers_with_request_context(self, client):
        """Test that error handlers work properly with Flask 2.x."""
        response = client.get('/nonexistent-route')
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data
        assert data['error'] == 'Not found'
        assert 'request_id' in data


class TestWerkzeugCVE202346136Protection:
    """
    Tests for CVE-2023-46136 protection in Werkzeug 3.0.1.

    CVE-2023-46136: DoS vulnerability in multipart form data parsing.
    Werkzeug versions prior to 3.0.1 had a vulnerability where crafted
    multipart data starting with CR/LF followed by large data without
    boundaries could cause excessive CPU usage.
    """

    def test_normal_multipart_upload(self, client):
        """Test that normal multipart uploads work correctly."""
        data = {
            'file': (io.BytesIO(b'test file content'), 'test.txt')
        }

        # This should work normally - the endpoint may not exist but
        # Werkzeug should parse the request without issues
        response = client.post('/api/documents',
                              data=data,
                              content_type='multipart/form-data')

        # We expect 401, 404, or other application error, not a 500 or timeout
        # The key is that Werkzeug 3.0.1 doesn't hang or consume excessive CPU
        assert response.status_code in [401, 404, 405, 400]

    def test_large_multipart_with_proper_boundaries(self, client):
        """Test that large files with proper boundaries are handled correctly."""
        # Create a larger file (1MB) with proper multipart boundaries
        large_content = b'A' * (1024 * 1024)
        data = {
            'file': (io.BytesIO(large_content), 'large_file.txt')
        }

        response = client.post('/api/documents',
                              data=data,
                              content_type='multipart/form-data')

        # Should not hang or timeout - Werkzeug 3.0.1 handles this efficiently
        assert response.status_code in [401, 404, 405, 400, 413]

    def test_malformed_multipart_doesnt_cause_dos(self, client):
        """
        Test that malformed multipart data doesn't cause DoS.

        In Werkzeug < 3.0.1, data starting with CR/LF without proper
        boundaries could cause excessive CPU usage. Version 3.0.1 fixes this.
        """
        # Craft data that starts with CR/LF followed by data without boundaries
        malformed_data = b'\r\n' + b'X' * 10000

        response = client.post('/api/documents',
                              data=malformed_data,
                              content_type='multipart/form-data; boundary=----WebKitFormBoundary')

        # The request should be rejected quickly without consuming excessive CPU
        # Status code should be 400 (Bad Request) or similar, not timeout
        assert response.status_code in [400, 401, 404, 405, 422]


class TestApplicationEndpoints:
    """Tests for core application endpoints."""

    def test_index_endpoint(self, client):
        """Test the index endpoint returns correct data."""
        response = client.get('/')
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'ProjectHub API'
        assert data['version'] == '1.0.0'
        assert data['status'] == 'running'

    def test_health_endpoint(self, client):
        """Test the health check endpoint."""
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

    def test_cors_headers_present(self, client):
        """Test that CORS headers are properly set."""
        response = client.get('/', headers={'Origin': 'http://example.com'})
        assert response.status_code == 200
        # Flask-CORS 4.0.0 should add CORS headers
        assert 'Access-Control-Allow-Origin' in response.headers


class TestDependencyVersions:
    """Tests to verify correct dependency versions are loaded."""

    def test_flask_version(self):
        """Verify Flask 2.3.3 is being used."""
        import flask
        # Check that we're using Flask 2.x or higher
        major, minor = map(int, flask.__version__.split('.')[:2])
        assert major >= 2, "Flask version should be 2.x or higher"
        if major == 2:
            assert minor >= 3, "Flask version should be 2.3 or higher"

    def test_werkzeug_version(self):
        """Verify Werkzeug 3.0.1 or higher is being used (CVE-2023-46136 fix)."""
        import werkzeug
        # Check that we're using Werkzeug 3.0.1 or higher
        version_parts = werkzeug.__version__.split('.')
        major = int(version_parts[0])
        minor = int(version_parts[1])
        patch = int(version_parts[2]) if len(version_parts) > 2 else 0

        assert major >= 3, "Werkzeug major version should be 3 or higher"
        if major == 3 and minor == 0:
            assert patch >= 1, "Werkzeug 3.0.x should be 3.0.1 or higher (CVE-2023-46136 fix)"

    def test_jinja2_version(self):
        """Verify Jinja2 3.1.x is being used (compatible with Flask 2.3)."""
        import jinja2
        major, minor = map(int, jinja2.__version__.split('.')[:2])
        assert major >= 3, "Jinja2 version should be 3.x or higher"
        if major == 3:
            assert minor >= 1, "Jinja2 version should be 3.1.x or higher"


class TestRequestMetadata:
    """Tests for request metadata handling."""

    def test_request_metadata_captured(self, client):
        """Test that request metadata is properly captured."""
        response = client.get('/', headers={
            'User-Agent': 'TestAgent/1.0'
        })
        assert response.status_code == 200
        # The before_request hook should have captured metadata
        # without causing errors with Flask 2.x API

    def test_multiple_requests_handle_context_properly(self, client):
        """Test that multiple requests handle context properly."""
        # Make multiple requests to ensure context handling is stable
        for i in range(5):
            response = client.get('/api/health')
            assert response.status_code == 200
            data = response.get_json()
            assert data['status'] == 'healthy'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
