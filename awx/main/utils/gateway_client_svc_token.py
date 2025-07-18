"""
Gateway API client for AAP Gateway interactions with Service Tokens.

This module provides a client class to interact with the AAP Gateway REST API,
specifically for creating authenticators and mapping configurations.
"""

import requests
import logging
from typing import Dict, Optional
from awx.main.utils.gateway_client import GatewayClient, GatewayAPIError


logger = logging.getLogger(__name__)


class GatewayClientSVCToken(GatewayClient):
    """Client for AAP Gateway REST API interactions."""

    def __init__(self, resource_api_client=None, command=None):
        """Initialize Gateway client.

        Args:
            resource_api_client: Resource API Client for Gateway leveraging service tokens
        """
        super().__init__(
            base_url=resource_api_client.base_url,
            username=resource_api_client.jwt_user_id,
            password="required-in-GatewayClient-authenticate()-but-unused-by-GatewayClientSVCToken",
            skip_verify=(not resource_api_client.verify_https),
            skip_session_init=True,
            command=command,
        )
        self.resource_api_client = resource_api_client
        # Authentication state
        self._authenticated = True

    def authenticate(self) -> bool:
        """Overload the base class method to always return True.

        Returns:
            bool: True always
        """

        return True

    def _ensure_authenticated(self):
        """Refresh JWT service token"""
        self.resource_api_client.refresh_jwt()

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> requests.Response:
        """Make a service token authenticated request to the Gateway API.

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

        try:
            response = self.resource_api_client._make_request(method=method, path=endpoint, data=data, params=params)

            # Log request details
            logger.debug(f"{method.upper()} {self.base_url}{endpoint} - Status: {response.status_code}")

            return response

        except requests.RequestException as e:
            raise GatewayAPIError(f"Request failed: {str(e)}")
