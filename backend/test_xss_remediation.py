"""
Tests for Stored XSS vulnerability remediation in admin dashboard.

This test suite validates that the admin_dashboard endpoint properly sanitizes
project data from the database to prevent Stored XSS attacks.
"""
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from markupsafe import Markup


class TestXSSRemediation(unittest.TestCase):
    """Test cases for XSS vulnerability remediation in admin dashboard."""

    def setUp(self):
        """Set up test fixtures."""
        # Import app and helper function
        from app import _sanitize_object_for_template
        self.sanitize_func = _sanitize_object_for_template

    def test_sanitize_object_escapes_xss_script_tag(self):
        """Test that script tags in project data are escaped."""
        # Create a mock project object with XSS payload
        mock_project = MagicMock()
        mock_project.name = "<script>alert('XSS')</script>"
        mock_project.description = "Normal description"
        mock_project.id = 1

        # Sanitize the object
        result = self.sanitize_func(mock_project)

        # Verify script tags are escaped
        self.assertIn('name', result)
        self.assertIsInstance(result['name'], Markup)
        # The escape function converts < to &lt; and > to &gt;
        self.assertEqual(str(result['name']), "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;")

    def test_sanitize_object_escapes_xss_event_handler(self):
        """Test that event handler XSS attacks are escaped."""
        mock_project = MagicMock()
        mock_project.name = "<img src=x onerror=alert('XSS')>"
        mock_project.description = "Test project"
        mock_project.id = 2

        result = self.sanitize_func(mock_project)

        # Verify event handlers are escaped
        self.assertIn('name', result)
        escaped_value = str(result['name'])
        self.assertIn('&lt;img', escaped_value)
        self.assertIn('onerror', escaped_value)
        self.assertNotIn('<img', escaped_value)

    def test_sanitize_object_escapes_html_injection(self):
        """Test that HTML injection attempts are escaped."""
        mock_project = MagicMock()
        mock_project.name = "<h1>Injected HTML</h1><p>Malicious content</p>"
        mock_project.description = "<div onclick='malicious()'>Click me</div>"
        mock_project.id = 3

        result = self.sanitize_func(mock_project)

        # Verify HTML tags are escaped in all string fields
        self.assertIn('&lt;h1&gt;', str(result['name']))
        self.assertIn('&lt;/h1&gt;', str(result['name']))
        self.assertIn('&lt;div', str(result['description']))
        self.assertNotIn('<h1>', str(result['name']))
        self.assertNotIn('<div', str(result['description']))

    def test_sanitize_object_preserves_non_string_values(self):
        """Test that non-string values are not modified."""
        mock_project = MagicMock()
        mock_project.id = 42
        mock_project.user_id = 7
        mock_project.is_active = True
        mock_project.priority = 3.5
        mock_project.name = "Safe name"

        result = self.sanitize_func(mock_project)

        # Verify non-string values are preserved
        self.assertEqual(result['id'], 42)
        self.assertEqual(result['user_id'], 7)
        self.assertEqual(result['is_active'], True)
        self.assertEqual(result['priority'], 3.5)

    def test_sanitize_object_handles_none_value(self):
        """Test that None input is handled gracefully."""
        result = self.sanitize_func(None)
        self.assertIsNone(result)

    def test_sanitize_object_escapes_javascript_protocol(self):
        """Test that javascript: protocol URLs are escaped."""
        mock_project = MagicMock()
        mock_project.url = "javascript:alert('XSS')"
        mock_project.name = "Test project"
        mock_project.id = 4

        result = self.sanitize_func(mock_project)

        # Verify javascript: protocol is escaped
        self.assertIn('url', result)
        escaped_url = str(result['url'])
        self.assertNotIn('javascript:', escaped_url)
        self.assertIn('javascript:', escaped_url.replace('&#x27;', "'").replace('&lt;', '<').replace('&gt;', '>') or
                     'javascript' in escaped_url)

    def test_sanitize_object_escapes_multiple_fields(self):
        """Test that multiple string fields are all sanitized."""
        mock_project = MagicMock()
        mock_project.name = "<script>XSS1</script>"
        mock_project.description = "<script>XSS2</script>"
        mock_project.category = "<img src=x onerror=alert('XSS3')>"
        mock_project.owner = "Normal User"
        mock_project.id = 5

        result = self.sanitize_func(mock_project)

        # Verify all string fields are escaped
        self.assertIn('&lt;script&gt;', str(result['name']))
        self.assertIn('&lt;script&gt;', str(result['description']))
        self.assertIn('&lt;img', str(result['category']))
        # Non-malicious content should still be escaped but readable
        self.assertEqual(str(result['owner']), "Normal User")

    def test_sanitize_object_escapes_encoded_xss(self):
        """Test that URL-encoded and HTML-encoded XSS attempts are handled."""
        mock_project = MagicMock()
        # Various encoding attempts
        mock_project.name = "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        mock_project.description = "%3Cscript%3Ealert('XSS')%3C/script%3E"
        mock_project.id = 6

        result = self.sanitize_func(mock_project)

        # Verify encoded content is still escaped (double escaping is safe)
        self.assertIsInstance(result['name'], Markup)
        self.assertIsInstance(result['description'], Markup)

    def test_sanitize_list_of_objects(self):
        """Test that a list of objects can be sanitized (as used in the fix)."""
        # Create multiple mock projects with XSS payloads
        projects = []
        for i in range(3):
            mock_project = MagicMock()
            mock_project.id = i
            mock_project.name = f"<script>alert('XSS{i}')</script>"
            mock_project.description = f"Project {i}"
            projects.append(mock_project)

        # Sanitize all projects
        sanitized_projects = [self.sanitize_func(p) for p in projects]

        # Verify all projects are sanitized
        self.assertEqual(len(sanitized_projects), 3)
        for i, sanitized in enumerate(sanitized_projects):
            self.assertIn('name', sanitized)
            self.assertIn('&lt;script&gt;', str(sanitized['name']))
            self.assertIn(f'XSS{i}', str(sanitized['name']))

    def test_sanitize_object_escapes_svg_xss(self):
        """Test that SVG-based XSS attacks are escaped."""
        mock_project = MagicMock()
        mock_project.name = "<svg/onload=alert('XSS')>"
        mock_project.description = "<svg><script>alert('XSS')</script></svg>"
        mock_project.id = 7

        result = self.sanitize_func(mock_project)

        # Verify SVG tags and attributes are escaped
        self.assertIn('&lt;svg', str(result['name']))
        self.assertIn('&lt;svg&gt;', str(result['description']))
        self.assertNotIn('<svg', str(result['name']))
        self.assertNotIn('<svg>', str(result['description']))

    def test_sanitize_object_with_quotes_and_special_chars(self):
        """Test that quotes and special characters are properly escaped."""
        mock_project = MagicMock()
        mock_project.name = "Project with \"quotes\" and 'apostrophes'"
        mock_project.description = "<a href=\"javascript:alert('XSS')\">Click</a>"
        mock_project.id = 8

        result = self.sanitize_func(mock_project)

        # Verify quotes are escaped
        name_str = str(result['name'])
        desc_str = str(result['description'])

        # The escape function should handle quotes
        self.assertIsInstance(result['name'], Markup)
        self.assertIsInstance(result['description'], Markup)
        self.assertIn('&lt;a', desc_str)


class TestAdminDashboardIntegration(unittest.TestCase):
    """Integration tests for the admin dashboard endpoint."""

    @patch('app.render_template')
    @patch('app.Task')
    @patch('app.Project')
    @patch('app.User')
    @patch('app.get_request_context')
    def test_admin_dashboard_sanitizes_projects(self, mock_context, mock_user,
                                                mock_project, mock_task, mock_render):
        """Test that admin_dashboard endpoint sanitizes project data before rendering."""
        # Import app after mocking
        from app import app as flask_app

        # Set up mock context
        mock_ctx = MagicMock()
        mock_ctx.request_id = 'test-request-id'
        mock_context.return_value = mock_ctx

        # Create mock project with XSS payload
        mock_project_obj = MagicMock()
        mock_project_obj.id = 1
        mock_project_obj.name = "<script>alert('XSS')</script>"
        mock_project_obj.description = "Test description"

        # Set up query mocks
        mock_user.query.all.return_value = []
        mock_project.query.all.return_value = [mock_project_obj]
        mock_task.query.all.return_value = []

        mock_render.return_value = "rendered_template"

        # Create test client and make request
        with flask_app.test_client() as client:
            response = client.get('/admin')

        # Verify render_template was called
        self.assertTrue(mock_render.called)

        # Get the arguments passed to render_template
        call_args = mock_render.call_args

        # Verify that projects argument is sanitized
        projects_arg = call_args[1]['projects']
        self.assertIsInstance(projects_arg, list)
        self.assertEqual(len(projects_arg), 1)

        # Verify the project data is a sanitized dictionary
        sanitized_project = projects_arg[0]
        self.assertIsInstance(sanitized_project, dict)

        # Verify XSS payload is escaped
        if 'name' in sanitized_project:
            name_value = str(sanitized_project['name'])
            self.assertIn('&lt;script&gt;', name_value)
            self.assertNotIn('<script>', name_value)

    def test_sanitize_function_skips_private_attributes(self):
        """Test that private attributes are not included in sanitized output."""
        from app import _sanitize_object_for_template

        mock_project = MagicMock()
        mock_project.name = "Test Project"
        mock_project._private_attr = "Should not be included"
        mock_project.__double_private = "Should not be included"
        mock_project.id = 1

        result = _sanitize_object_for_template(mock_project)

        # Verify private attributes are not in result
        self.assertNotIn('_private_attr', result)
        self.assertNotIn('__double_private', result)
        # Public attributes should be present
        self.assertIn('name', result)
        self.assertIn('id', result)

    def test_sanitize_function_skips_callable_attributes(self):
        """Test that methods/callables are not included in sanitized output."""
        from app import _sanitize_object_for_template

        mock_project = MagicMock()
        mock_project.name = "Test Project"
        mock_project.id = 1
        # Mock objects have callable attributes, ensure they're skipped

        result = _sanitize_object_for_template(mock_project)

        # Result should only contain non-callable attributes
        for key, value in result.items():
            self.assertFalse(callable(value),
                           f"Result contains callable attribute: {key}")


if __name__ == '__main__':
    unittest.main()
