"""MCP tools for platform management on Vectra On-Premise."""

from typing import Literal, Annotated
from pydantic import Field
import json

from utils.validators import validate_date_range

class ManagementMCPTools:
    """MCP tools for Vectra On-Premise platform management."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all platform management tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_platform_users)

    async def list_platform_users(
        self,
        role: Annotated[
            str | None, 
            Field(description="Filter by user role")
        ] = None,
        last_login_after : Annotated[
            str | None, 
            Field(description="Filter by last login date in ISO format (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        username: Annotated[
            str | None, 
            Field(description="Filter by username")
        ] = None,
        account_type: Annotated[
            Literal["local", "SAML"] | None, 
            Field(description="Filter by account type (local or SAML)")
        ] = None,
        authentication_profile: Annotated[
            str | None, 
            Field(description="Filter by authentication profile")
        ] = None,
        limit: Annotated[
            int, 
            Field(description="Maximum number of users to return. Defaults to 1000", ge=1, le=1000)
        ] = 1000
    ) -> str:
        """
        List users in the Vectra On-Premise platform.
        
        Returns:
            str: JSON string with list of users.
        """

        try:
            search_params = {}
            
            if role:
                search_params['role'] = role
            if username:
                search_params['username'] = username
            if account_type:
                search_params['account_type'] = account_type
            if authentication_profile:
                search_params['authentication_profile'] = authentication_profile

            # Add last login filter if provided
            # Validate and convert date string to datetime object
            last_login_after, end_date = validate_date_range(last_login_after, None)
            if last_login_after:
                search_params['last_login_gte'] = last_login_after

            all_users = await self.client.get_users(**search_params)

            # Extract user list from response
            user_list = all_users.get('results', [])
            if not user_list:
                return "No users found."
            
            # Limit results if specified
            if limit and len(user_list) > limit:
                user_list = user_list[:limit]
            
            # Get user count
            user_count = len(user_list)

            # Return formatted JSON response
            return json.dumps({"user_count": user_count, "user_list": user_list}, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to list users: {str(e)}")

    