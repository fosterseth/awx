"""
Gateway API client for AAP Gateway interactions.

This module provides a client class to interact with the AAP Gateway REST API,
specifically for creating authenticators and mapping configurations.
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin


logger = logging.getLogger(__name__)


class GatewayAPIError(Exception):
    """Exception raised for Gateway API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(self.message)


class GatewayClient:
    """Client for AAP Gateway REST API interactions."""

    def __init__(self, base_url: str, username: str, password: str, skip_verify: bool = False):
        """Initialize Gateway client.

        Args:
            base_url: Base URL of the AAP Gateway instance
            username: Username for authentication
            password: Password for authentication
            skip_verify: Skip SSL certificate verification
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.skip_verify = skip_verify

        # Initialize session
        self.session = requests.Session()

        # Configure SSL verification
        if skip_verify:
            self.session.verify = False
            # Disable SSL warnings when verification is disabled
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Set default headers
        self.session.headers.update(
            {
                'User-Agent': 'AWX-Gateway-Migration-Client/1.0',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            }
        )

        # Authentication state
        self._authenticated = False

    def authenticate(self) -> bool:
        """Authenticate with the Gateway using HTTP Basic Authentication.

        Returns:
            bool: True if authentication successful, False otherwise

        Raises:
            GatewayAPIError: If authentication fails
        """
        try:
            # Set up HTTP Basic Authentication
            from requests.auth import HTTPBasicAuth

            self.session.auth = HTTPBasicAuth(self.username, self.password)

            # Test authentication by making a simple request to the API
            test_url = urljoin(self.base_url, '/api/gateway/v1/authenticators/')

            response = self.session.get(test_url)

            if response.status_code in [200, 401]:  # 401 means auth is working but might need permissions
                self._authenticated = True
                logger.info("Successfully authenticated with Gateway using Basic Auth")
                return True
            else:
                error_msg = f"Authentication test failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg += f": {error_data}"
                except requests.exceptions.JSONDecodeError:
                    error_msg += f": {response.text}"

                raise GatewayAPIError(error_msg, response.status_code, response.json() if response.content else None)

        except requests.RequestException as e:
            raise GatewayAPIError(f"Network error during authentication: {str(e)}")

    def _ensure_authenticated(self):
        """Ensure the client is authenticated, authenticate if needed."""
        if not self._authenticated:
            self.authenticate()

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> requests.Response:
        """Make an authenticated request to the Gateway API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint (without base URL)
            data: JSON data to send in request body
            params: Query parameters

        Returns:
            requests.Response: The response object

        Raises:
            GatewayAPIError: If request fails
        """
        self._ensure_authenticated()

        url = urljoin(self.base_url, endpoint.lstrip('/'))

        try:
            response = self.session.request(method=method.upper(), url=url, json=data, params=params)

            # Log request details
            logger.debug(f"{method.upper()} {url} - Status: {response.status_code}")

            return response

        except requests.RequestException as e:
            raise GatewayAPIError(f"Request failed: {str(e)}")

    def create_authenticator(self, authenticator_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new authenticator in Gateway.

        Args:
            authenticator_config: Authenticator configuration dictionary

        Returns:
            dict: Created authenticator data

        Raises:
            GatewayAPIError: If creation fails
        """
        endpoint = '/api/gateway/v1/authenticators/'

        try:
            response = self._make_request('POST', endpoint, data=authenticator_config)

            if response.status_code == 201:
                result = response.json()
                logger.info(f"Successfully created authenticator: {result.get('name', 'Unknown')}")
                return result
            else:
                error_msg = f"Failed to create authenticator. Status: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg += f", Error: {error_data}"
                except requests.exceptions.JSONDecodeError:
                    error_msg += f", Response: {response.text}"

                raise GatewayAPIError(error_msg, response.status_code, response.json() if response.content else None)

        except requests.RequestException as e:
            raise GatewayAPIError(f"Failed to create authenticator: {str(e)}")

    def create_authenticator_map(self, authenticator_id: int, mapper_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new authenticator map in Gateway.

        Args:
            authenticator_id: ID of the authenticator to create map for
            mapper_config: Mapper configuration dictionary

        Returns:
            dict: Created mapper data

        Raises:
            GatewayAPIError: If creation fails
        """
        endpoint = '/api/gateway/v1/authenticator_maps/'

        try:

            response = self._make_request('POST', endpoint, data=mapper_config)

            if response.status_code == 201:
                result = response.json()
                logger.info(f"Successfully created authenticator map: {result.get('name', 'Unknown')}")
                return result
            else:
                error_msg = f"Failed to create authenticator map. Status: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg += f", Error: {error_data}"
                except requests.exceptions.JSONDecodeError:
                    error_msg += f", Response: {response.text}"

                raise GatewayAPIError(error_msg, response.status_code, response.json() if response.content else None)

        except requests.RequestException as e:
            raise GatewayAPIError(f"Failed to create authenticator map: {str(e)}")

    def get_authenticators(self, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Get list of authenticators from Gateway.

        Args:
            params: Optional query parameters

        Returns:
            list: List of authenticator configurations

        Raises:
            GatewayAPIError: If request fails
        """
        endpoint = '/api/gateway/v1/authenticators/'

        try:
            response = self._make_request('GET', endpoint, params=params)

            if response.status_code == 200:
                result = response.json()
                # Handle paginated response
                if isinstance(result, dict) and 'results' in result:
                    return result['results']
                return result
            else:
                error_msg = f"Failed to get authenticators. Status: {response.status_code}"
                raise GatewayAPIError(error_msg, response.status_code)

        except requests.RequestException as e:
            raise GatewayAPIError(f"Failed to get authenticators: {str(e)}")

    def get_authenticator_maps(self, authenticator_id: int) -> List[Dict[str, Any]]:
        """Get list of maps for a specific authenticator.

        Args:
            authenticator_id: ID of the authenticator

        Returns:
            list: List of authenticator maps

        Raises:
            GatewayAPIError: If request fails
        """
        endpoint = f'/api/gateway/v1/authenticators/{authenticator_id}/maps/'

        try:
            response = self._make_request('GET', endpoint)

            if response.status_code == 200:
                result = response.json()
                # Handle paginated response
                if isinstance(result, dict) and 'results' in result:
                    return result['results']
                return result
            else:
                error_msg = f"Failed to get authenticator maps. Status: {response.status_code}"
                raise GatewayAPIError(error_msg, response.status_code)

        except requests.RequestException as e:
            raise GatewayAPIError(f"Failed to get authenticator maps: {str(e)}")

    def create_github_authenticator(
        self, name: str, client_id: str, client_secret: str, enabled: bool = True, create_objects: bool = False, remove_users: bool = False
    ) -> Dict[str, Any]:
        """Create a GitHub authenticator with the specified configuration.

        Args:
            name: Name for the authenticator
            client_id: GitHub OAuth App Client ID
            client_secret: GitHub OAuth App Client Secret
            enabled: Whether authenticator should be enabled
            create_objects: Whether to create users/orgs/teams automatically
            remove_users: Whether to remove users when they lose access

        Returns:
            dict: Created authenticator data
        """
        config = {
            "name": name,
            "type": "ansible_base.authentication.authenticator_plugins.github",
            "enabled": enabled,
            "create_objects": create_objects,
            "remove_users": remove_users,
            "configuration": {"KEY": client_id, "SECRET": client_secret},
        }

        return self.create_authenticator(config)

    def close(self):
        """Close the session and clean up resources."""
        if self.session:
            self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
