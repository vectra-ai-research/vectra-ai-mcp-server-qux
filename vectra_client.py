"""Vectra AI On-Premise API client wrapper with authentication and rate limiting."""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlencode, urlparse, parse_qs

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config import VectraConfig
from utils.logging import get_logger


class VectraAPIError(Exception):
    """Custom exception for Vectra API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class VectraAuthenticationError(VectraAPIError):
    """Authentication-related API errors."""
    pass


class VectraRateLimitError(VectraAPIError):
    """Rate limiting API errors."""
    pass


class VectraNotFoundError(VectraAPIError):
    """Resource not found API errors."""
    pass


class APIKeyManager:
    """Manages API key authentication for on-premise Vectra."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.logger = get_logger(__name__)
    
    def get_auth_header(self) -> str:
        """Get the authorization header for API key authentication."""
        return f"Token {self.api_key}"


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, requests_per_period: int, period: int):
        self.requests_per_period = requests_per_period
        self.period = period
        self.tokens = requests_per_period
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire a token for rate limiting."""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Add tokens based on time passed
            self.tokens = min(
                self.requests_per_period,
                self.tokens + (time_passed * self.requests_per_period / self.period)
            )
            self.last_update = now
            
            if self.tokens < 1:
                # Calculate wait time
                wait_time = (1 - self.tokens) * self.period / self.requests_per_period
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class VectraClient:
    """Vectra AI On-Premise API client with authentication and rate limiting."""
    
    def __init__(self, config: VectraConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Initialize API key manager
        self.api_key_manager = APIKeyManager(
            api_key=config.api_key
        )
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            requests_per_period=config.rate_limit_requests,
            period=config.rate_limit_period
        )
        
        # HTTP client configuration
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.request_timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            verify=config.verify_ssl
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException))
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make authenticated HTTP request to Vectra On-Premise API."""
        await self.rate_limiter.acquire()
        
        # Get authorization header
        auth_header = self.api_key_manager.get_auth_header()
        
        # Build URL
        url = urljoin(self.config.api_base_url + "/", endpoint.lstrip("/"))
        
        # Prepare headers
        headers = {
            "Authorization": auth_header,
            "Accept": "application/json",
            "User-Agent": f"VectraMCPServer-OnPrem/1.0.0"
        }
        
        # Log request
        self.logger.debug(f"Making {method} request to {url}", extra={
            "method": method,
            "url": url,
            "params": params
        })
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers
            )
            
            # Handle response
            if response.status_code == 401:
                raise VectraAuthenticationError(
                    "Authentication failed - check credentials",
                    status_code=401
                )
            elif response.status_code == 403:
                raise VectraAuthenticationError(
                    "Access forbidden - insufficient permissions",
                    status_code=403
                )
            elif response.status_code == 404:
                raise VectraNotFoundError(
                    "Resource not found",
                    status_code=404
                )
            elif response.status_code == 429:
                raise VectraRateLimitError(
                    "Rate limit exceeded",
                    status_code=429
                )
            elif not response.is_success:
                error_msg = f"API request failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_msg += f": {error_data['message']}"
                except:
                    error_msg += f": {response.text}"
                
                raise VectraAPIError(
                    error_msg,
                    status_code=response.status_code,
                    response_data=error_data if 'error_data' in locals() else None
                )
            
            # Parse JSON response
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            else:
                return {"data": response.text}
        
        except httpx.HTTPStatusError as e:
            raise VectraAPIError(f"HTTP error: {e}", status_code=e.response.status_code)
        except httpx.RequestError as e:
            raise VectraAPIError(f"Request error: {e}")
    
    async def _get_all_pages(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 1000
    ) -> Dict[str, Any]:
        """
        Fetch all pages from a paginated endpoint and return combined results.
        
        Args:
            endpoint: API endpoint to call
            params: Query parameters for the request
            max_pages: Maximum number of pages to fetch (safety limit)
            
        Returns:
            Dict with same structure as single page response but with all results combined:
            {
                "count": total_count,
                "next": null,
                "previous": null,
                "results": [all_items_from_all_pages]
            }
        """
        if params is None:
            params = {}
        
        all_results = []
        current_params = params.copy()
        pages_fetched = 0
        
        # Remove any existing page parameter to start from page 1
        current_params.pop("page", None)
        
        self.logger.debug(f"Starting auto-pagination for {endpoint}")
        
        while pages_fetched < max_pages:
            try:
                response = await self._make_request("GET", endpoint, params=current_params)
                
                # Check if this is a paginated response
                if not isinstance(response, dict) or "results" not in response:
                    # Not a paginated response, return as-is
                    return response
                
                # Add results from current page
                page_results = response.get("results", [])
                all_results.extend(page_results)
                pages_fetched += 1
                
                self.logger.debug(f"Fetched page {pages_fetched}, got {len(page_results)} items, total: {len(all_results)}")
                
                # Check if there's a next page
                next_url = response.get("next")
                if not next_url:
                    # No more pages
                    break
                
                # Extract page number from next URL
                try:
                    parsed_url = urlparse(next_url)
                    query_params = parse_qs(parsed_url.query)
                    next_page = query_params.get("page", [None])[0]
                    
                    if next_page:
                        current_params["page"] = int(next_page)
                    else:
                        # No page parameter in next URL, break to avoid infinite loop
                        break
                        
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Could not parse next page URL: {next_url}, error: {e}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error during pagination at page {pages_fetched + 1}: {e}")
                # Return what we have so far
                break
        
        if pages_fetched >= max_pages:
            self.logger.warning(f"Reached maximum page limit ({max_pages}) for {endpoint}")
        
        # Return combined response with same structure
        return {
            "count": len(all_results),
            "next": None,
            "previous": None,
            "results": all_results
        }
    
    # Account endpoints
    async def get_accounts(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        account_type: Optional[str] = None,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        min_threat: Optional[int] = None,
        max_threat: Optional[int] = None,
        min_certainty: Optional[int] = None,
        max_certainty: Optional[int] = None,
        tags: Optional[str] = None,
        name: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of accounts with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "account_type": account_type,
            "state": state,
            "severity": severity,
            "min_threat": min_threat,
            "max_threat": max_threat,
            "min_certainty": min_certainty,
            "max_certainty": max_certainty,
            "tags": tags,
            "name": name,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("accounts", params)
        else:
            return await self._make_request("GET", "accounts", params=params)
    
    async def get_account(
        self, 
        account_id: int,
        fields: Optional[List[str]] = None,
        exclude_fields: Optional[List[str]] = None,
        include_access_history: Optional[bool] = None,
        include_detection_summaries: Optional[bool] = None,
        include_external: Optional[bool] = None,
        src_linked_account: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get specific account by ID with optional field filtering and additional parameters."""
        params = {}
        if fields:
            params["fields"] = ",".join(fields)
        if exclude_fields:
            params["exclude_fields"] = ",".join(exclude_fields)
        if include_access_history is not None:
            params["include_access_history"] = include_access_history
        if include_detection_summaries is not None:
            params["include_detection_summaries"] = include_detection_summaries
        if include_external is not None:
            params["include_external"] = include_external
        if src_linked_account:
            params["src_linked_account"] = src_linked_account
        return await self._make_request("GET", f"accounts/{account_id}", params=params)
    
    # Host endpoints
    async def get_hosts(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        min_threat: Optional[int] = None,
        max_threat: Optional[int] = None,
        min_certainty: Optional[int] = None,
        max_certainty: Optional[int] = None,
        is_key_asset: Optional[bool] = None,
        name: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of hosts with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "state": state,
            "severity": severity,
            "min_threat": min_threat,
            "max_threat": max_threat,
            "min_certainty": min_certainty,
            "max_certainty": max_certainty,
            "is_key_asset": is_key_asset,
            "name": name,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("hosts", params)
        else:
            return await self._make_request("GET", "hosts", params=params)
    
    async def get_host(self, host_id: int) -> Dict[str, Any]:
        """Get specific host by ID."""
        return await self._make_request("GET", f"hosts/{host_id}")
    
    # Search endpoints (on-premise specific)
    async def search_accounts(
        self,
        query_string: str,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False
    ) -> Dict[str, Any]:
        """Search accounts using Lucene query string."""
        params = {k: v for k, v in {
            "query_string": query_string,
            "page": page,
            "page_size": page_size,
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("search/accounts", params)
        else:
            return await self._make_request("GET", "search/accounts", params=params)
    
    async def search_hosts(
        self,
        query_string: str,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False
    ) -> Dict[str, Any]:
        """Search hosts using Lucene query string."""
        params = {k: v for k, v in {
            "query_string": query_string,
            "page": page,
            "page_size": page_size,
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("search/hosts", params)
        else:
            return await self._make_request("GET", "search/hosts", params=params)
    
    async def search_detections(
        self,
        query_string: str,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        auto_paginate: bool = False
    ) -> Dict[str, Any]:
        """Search detections using Lucene query string."""
        params = {k: v for k, v in {
            "query_string": query_string,
            "page": page,
            "page_size": page_size,
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("search/detections", params)
        else:
            return await self._make_request("GET", "search/detections", params=params)
    
    # Detection endpoints
    async def get_detections(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        category: Optional[str] = None,
        detection_category: Optional[str] = None,
        detection_type: Optional[str] = None,
        state: Optional[str] = None,
        certainty: Optional[int] = None,
        certainty_gte: Optional[int] = None,
        threat: Optional[int] = None,
        threat_gte: Optional[int] = None,
        src_ip: Optional[str] = None,
        host_id: Optional[int] = None,
        is_targeting_key_asset: Optional[bool] = None,
        last_timestamp: Optional[str] = None,
        last_timestamp_gte: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of detections with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "category": category,
            "detection_category": detection_category,
            "detection_type": detection_type,
            "state": state,
            "certainty": certainty,
            "certainty_gte": certainty_gte,
            "threat": threat,
            "threat_gte": threat_gte,
            "src_ip": src_ip,
            "host_id": host_id,
            "is_targeting_key_asset": is_targeting_key_asset,
            "last_timestamp": last_timestamp,
            "last_timestamp_gte": last_timestamp_gte,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("detections", params)
        else:
            return await self._make_request("GET", "detections", params=params)
    
    async def get_detection(self, detection_id: int) -> Dict[str, Any]:
        """Get specific detection by ID."""
        return await self._make_request("GET", f"detections/{detection_id}")
    
    # Detection Action endpoints
    async def mark_detection_fixed(self, detection_ids: list, fixed_status: bool) -> Dict[str, Any]:
        """Marks or unmark detection as fixed."""
        mark_data = {
            "detectionIdList": detection_ids,
            "mark_as_fixed": str(fixed_status).lower()
        }
        return await self._make_request("PATCH", "detections", json_data=mark_data)
    
    # Event endpoints
    async def get_events(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        category: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of events with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "category": category,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("events", params)
        else:
            return await self._make_request("GET", "events", params=params)
    
    # Assignment endpoints
    async def get_assignments(
        self,
        accounts: Optional[str] = None,
        assignees: Optional[str] = None,
        created_after: Optional[str] = None,
        hosts: Optional[str] = None,
        resolution: Optional[str] = None,
        resolved: Optional[bool] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of assignments with filtering."""
        params = {k: v for k, v in {
            "accounts": accounts,
            "assignees": assignees,
            "created_after": created_after,
            "hosts": hosts,
            "resolution": resolution,
            "resolved": resolved,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("assignments", params)
        else:
            return await self._make_request("GET", "assignments", params=params)
    
    async def get_assignment(self, assignment_id: int) -> Dict[str, Any]:
        """Get specific assignment by ID."""
        return await self._make_request("GET", f"assignments/{assignment_id}")
    
    async def create_assignment(self, assignment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new assignment."""
        return await self._make_request("POST", "assignments", json_data=assignment_data)
    
    async def delete_assignment(self, assignment_id: int) -> Dict[str, Any]:
        """Delete assignment by ID."""
        return await self._make_request("DELETE", f"assignment/{assignment_id}")
    
    async def update_assignment(self, assignment_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing assignment."""
        return await self._make_request("PUT", f"assignment/{assignment_id}", json_data=update_data)
    
    # Health endpoints
    async def get_health(self) -> Dict[str, Any]:
        """Get system health status."""
        return await self._make_request("GET", "health")
    
    # Notes endpoints
    async def add_account_note(self, account_id: int, note: str) -> Dict[str, Any]:
        """Add note to account."""
        note_data = {"note": note}
        return await self._make_request("POST", f"accounts/{account_id}/notes", json_data=note_data)
    
    async def add_host_note(self, host_id: int, note: str) -> Dict[str, Any]:
        """Add note to host."""
        note_data = {"note": note}
        return await self._make_request("POST", f"hosts/{host_id}/notes", json_data=note_data)
    
    async def add_detection_note(self, detection_id: int, note: str) -> Dict[str, Any]:
        """Add note to detection."""
        note_data = {"note": note}
        return await self._make_request("POST", f"detections/{detection_id}/notes", json_data=note_data)
    
    async def delete_account_note(self, account_id: int, note_id: int) -> Dict[str, Any]:
        """Delete note from account."""
        return await self._make_request("DELETE", f"accounts/{account_id}/notes/{note_id}")
    
    async def delete_host_note(self, host_id: int, note_id: int) -> Dict[str, Any]:
        """Delete note from host."""
        return await self._make_request("DELETE", f"hosts/{host_id}/notes/{note_id}")
    
    async def delete_detection_note(self, detection_id: int, note_id: int) -> Dict[str, Any]:
        """Delete note from detection."""
        return await self._make_request("DELETE", f"detections/{detection_id}/notes/{note_id}")
    
    # Tagging endpoints
    async def get_account_tags(self, account_id: int) -> Dict[str, Any]:
        """Get tags for account."""
        return await self._make_request("GET", f"tagging/account/{account_id}")
    
    async def update_account_tags(self, account_id: int, tags: List[str]) -> Dict[str, Any]:
        """Update tags for account."""
        tag_data = {"tags": tags}
        return await self._make_request("PATCH", f"tagging/account/{account_id}", json_data=tag_data)
    
    async def get_host_tags(self, host_id: int) -> Dict[str, Any]:
        """Get tags for host."""
        return await self._make_request("GET", f"tagging/host/{host_id}")
    
    async def update_host_tags(self, host_id: int, tags: List[str]) -> Dict[str, Any]:
        """Update tags for host."""
        tag_data = {"tags": tags}
        return await self._make_request("PATCH", f"tagging/host/{host_id}", json_data=tag_data)
    
    async def get_detection_tags(self, detection_id: int) -> Dict[str, Any]:
        """Get tags for detection."""
        return await self._make_request("GET", f"tagging/detection/{detection_id}")
    
    async def update_detection_tags(self, detection_id: int, tags: List[str]) -> Dict[str, Any]:
        """Update tags for detection."""
        tag_data = {"tags": tags}
        return await self._make_request("PATCH", f"tagging/detection/{detection_id}", json_data=tag_data)
    
    # User endpoints
    async def get_users(
        self,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        ordering: Optional[str] = None,
        username: Optional[str] = None,
        role: Optional[str] = None,
        account_type: Optional[str] = None,
        authentication_profile: Optional[str] = None,
        last_login_gte: Optional[str] = None,
        auto_paginate: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Get list of users with filtering."""
        params = {k: v for k, v in {
            "page": page,
            "page_size": page_size,
            "ordering": ordering,
            "username": username,
            "role": role,
            "account_type": account_type,
            "authentication_profile": authentication_profile,
            "last_login_gte": last_login_gte,
            **kwargs
        }.items() if v is not None}
        
        if auto_paginate:
            return await self._get_all_pages("users", params)
        else:
            return await self._make_request("GET", "users", params=params)
    
    async def get_user(self, user_id: int) -> Dict[str, Any]:
        """Get specific user by ID."""
        return await self._make_request("GET", f"users/{user_id}")
    
    # Search functionality
    async def search_by_name(self, name: str, entity_type: Optional[str] = None) -> Dict[str, Any]:
        """Search entities by name using Lucene query."""
        if entity_type == "account":
            return await self.search_accounts(f"name:{name}")
        elif entity_type == "host":
            return await self.search_hosts(f"name:{name}")
        else:
            # Search both accounts and hosts
            accounts = await self.search_accounts(f"name:{name}")
            hosts = await self.search_hosts(f"name:{name}")
            return {
                "accounts": accounts.get("results", []),
                "hosts": hosts.get("results", [])
            }