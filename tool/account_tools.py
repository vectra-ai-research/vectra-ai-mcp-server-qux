"""Account tools for security investigations on Vectra On-Premise."""

from typing import Literal, Annotated, List
from pydantic import Field
import json

class AccountMCPTools:
    """MCP tools for account analysis and management on Vectra On-Premise."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all account tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_accounts)
        self.vectra_mcp.tool()(self.get_account_details)
        self.vectra_mcp.tool()(self.add_account_note)
        self.vectra_mcp.tool()(self.delete_account_note)
        self.vectra_mcp.tool()(self.get_account_tags)
        self.vectra_mcp.tool()(self.update_account_tags)
    
    async def list_accounts(
        self,
        state: Annotated[
            Literal["active", "inactive"], 
            Field(description="Filter by account state (active, inactive)")
        ] = "active",
        ordering: Annotated[
            str, 
            Field(description="Order by field name. Use '-' prefix for descending order. Valid fields: last_detection_timestamp, t_score, c_score, id")
        ] = "-t_score",
        name: Annotated[
            str | None, 
            Field(description="Filter by account name. Can also perform partial word match.")
        ] = None,
        tags: Annotated[
            str | None, 
            Field(description="Filter for accounts with a particular tag")
        ] = None,
        threat_gte: Annotated[
            int | None, 
            Field(description="Filter by threat score greater than or equal to value", ge=0, le=99)
        ] = None,
        certainty_gte: Annotated[
            int | None, 
            Field(description="Filter by certainty score greater than or equal to value", ge=0, le=99)
        ] = None,
        limit: Annotated[
            int, 
            Field(description="Maximum number of accounts to return in the batch. None means no limit", ge=1, le=1000)
        ] = 1000
    ) -> str:
        """
        List accounts in Vectra On-Premise platform based on basic filters.

        This tool provides basic filtering capabilities for accounts. For advanced searches
        (e.g., specific account names, privilege levels, detection types, IP addresses, 
        operating systems, or complex queries), use the advanced_search_accounts tool instead.

        Basic filters supported:
        - state: active/inactive accounts
        - ordering: sort by t_score, c_score, last_detection_timestamp, or id
        - name: partial name matching
        - tags: specific tag filtering
        - threat_gte: minimum threat score
        - certainty_gte: minimum certainty score

        For specific searches like:
        - Finding accounts by exact name: use advanced_search_accounts
        - Finding accounts by privilege level: use advanced_search_accounts
        - Finding accounts with specific detection types: use advanced_search_accounts
        - Complex boolean queries: use advanced_search_accounts

        Returns:
            str: Formatted string with list of accounts.
        """
        try:
            params = locals().copy()

            # Remove non-query parameters
            exclude_params = {'self', 'limit'}

            search_params = {k: v for k, v in params.items()
                    if v is not None and k not in exclude_params}
            
            accounts_response = await self.client.get_accounts(**search_params)
            accounts = accounts_response.get("results", [])
            total_count = accounts_response.get("count")

            if not accounts:
                return "No accounts found matching the specified criteria."
            
            if limit and len(accounts) > limit:
                accounts = accounts[:limit]
            
            # Format the response as a JSON string
            return json.dumps({"total_count": total_count, "accounts": accounts}, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch accounts: {str(e)}")
     
    async def get_account_details(
        self,
        account_id: Annotated[int, Field(description="ID of the account in Vectra platform to retrieve details for", ge=1)],
        fields: Annotated[
            list[str] | None, 
            Field(description="Fields to return in the results. Available fields: id, url, name, state, threat, certainty, severity, account_type, tags, note, notes, note_modified_by, note_modified_timestamp, privilege_level, privilege_category, last_detection_timestamp, detection_set, probable_home, assignment, past_assignments")
        ] = None
    ) -> str:
        """
        Get complete detailed information about a specific account using the v2.5 accounts API endpoint.
        
        Severity Level Logic:
        The severity level is calculated based on threat and certainty scores:
        - Critical: threat >= 50 AND certainty >= 50
        - High: threat >= 50 AND certainty < 50
        - Medium: threat < 50 AND certainty >= 50
        - Low: threat < 50 AND certainty < 50
        - Unknown: default fallback
        
        Returns:
            str: Formatted string with detailed information about the account. It includes detections, scoring information, associated accounts, notes, and more.
            If the account is not found, returns a message indicating that no account was found with the specified ID.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            # Fetch account details using the v2.5 accounts API endpoint
            account_details = await self.client.get_account(
                account_id=account_id,
                fields=fields
            )
            
            # Check if the account was found
            if 'detail' in account_details and account_details['detail'] == 'Not found.':
                return f"No account found with ID: {account_id}."
            
            return json.dumps(account_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch account details: {str(e)}")
    
    async def add_account_note(
        self,
        account_id: Annotated[
            int, Field(ge=1, description="ID of the account to add note to")
        ],
        note: Annotated[
            str, 
            Field(description="Note text to add to the account.")
        ]
    ) -> str:
        """
        Add an investigation note to an account.
        
        Returns:
            str: Confirmation message with note details.
        """
        try:
            create_note = await self.client.add_account_note(account_id, note)
            return json.dumps(create_note, indent=2)
        except Exception as e:
            raise Exception(f"Failed to add note to account {account_id}: {str(e)}")
    
    async def delete_account_note(
        self,
        account_id: Annotated[
            int, Field(ge=1, description="ID of the account to delete note from")
        ],
        note_id: Annotated[
            int, Field(ge=1, description="ID of the note to delete")
        ]
    ) -> str:
        """
        Delete a note from an account.
        
        Returns:
            str: Confirmation message.
        """
        try:
            delete_result = await self.client.delete_account_note(account_id, note_id)
            return json.dumps(delete_result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to delete note {note_id} from account {account_id}: {str(e)}")
    
    async def get_account_tags(
        self,
        account_id: Annotated[
            int, Field(ge=1, description="ID of the account to get tags for")
        ]
    ) -> str:
        """
        Get tags for an account.
        
        Returns:
            str: JSON string with account tags.
        """
        try:
            tags = await self.client.get_account_tags(account_id)
            return json.dumps(tags, indent=2)
        except Exception as e:
            raise Exception(f"Failed to get tags for account {account_id}: {str(e)}")
    
    async def update_account_tags(
        self,
        account_id: Annotated[
            int, Field(ge=1, description="ID of the account to update tags for")
        ],
        tags: Annotated[
            List[str], Field(description="List of tags to set for the account")
        ]
    ) -> str:
        """
        Update tags for an account.
        
        Returns:
            str: Confirmation message with updated tags.
        """
        try:
            update_result = await self.client.update_account_tags(account_id, tags)
            return json.dumps(update_result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to update tags for account {account_id}: {str(e)}")
