"""Host tools for security investigations on Vectra On-Premise."""

from typing import Literal, Annotated, List
from pydantic import Field
import json

class HostMCPTools:
    """MCP tools for host analysis and management on Vectra On-Premise."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all host tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_hosts)
        self.vectra_mcp.tool()(self.get_host_details)
        self.vectra_mcp.tool()(self.add_host_note)
        self.vectra_mcp.tool()(self.delete_host_note)
        self.vectra_mcp.tool()(self.get_host_tags)
        self.vectra_mcp.tool()(self.update_host_tags)
    
    async def list_hosts(
        self,
        state: Annotated[
            Literal["active", "inactive"], 
            Field(description="Filter by host state (active, inactive)")
        ] = "active",
        ordering: Annotated[
            str, 
            Field(description="Order by field name. Use '-' prefix for descending order. Valid fields: last_detection_timestamp, t_score, c_score, id")
        ] = "-t_score",
        name: Annotated[
            str | None, 
            Field(description="Filter by host name. Can also perform partial word match.")
        ] = None,
        tags: Annotated[
            str | None, 
            Field(description="Filter for hosts with a particular tag")
        ] = None,
        threat_gte: Annotated[
            int | None, 
            Field(description="Filter by threat score greater than or equal to value", ge=0, le=99)
        ] = None,
        certainty_gte: Annotated[
            int | None, 
            Field(description="Filter by certainty score greater than or equal to value", ge=0, le=99)
        ] = None,
        is_key_asset: Annotated[
            bool | None, 
            Field(description="Filter for key assets. do not use by default. Use it only if you know what you are doing.")
        ] = None,
        limit: Annotated[
            int, 
            Field(description="Maximum number of hosts to return in the batch. None means no limit", ge=1, le=1000)
        ] = 1000
    ) -> str:
        """
        List hosts in Vectra On-Premise platform based on basic filters.

        This tool provides basic filtering capabilities for hosts. For advanced searches
        (e.g., specific IP addresses, host names, operating systems, sensor names, 
        key assets, or complex queries), use the advanced_search_hosts tool instead.

        Basic filters supported:
        - state: active/inactive hosts
        - ordering: sort by t_score, c_score, last_detection_timestamp, or id
        - name: partial name matching
        - tags: specific tag filtering
        - threat_gte: minimum threat score
        - certainty_gte: minimum certainty score
        - is_key_asset: filter key assets

        For specific searches like:
        - Finding hosts by IP address: use advanced_search_hosts
        - Finding hosts by exact name: use advanced_search_hosts
        - Finding Windows/Linux hosts: use advanced_search_hosts
        - Finding hosts by sensor name: use advanced_search_hosts
        - Finding hosts with specific detection types: use advanced_search_hosts
        - Complex boolean queries: use advanced_search_hosts

        Returns:
            str: Formatted string with list of hosts.
        """
        try:
            params = locals().copy()

            # Remove non-query parameters
            exclude_params = {'self', 'limit'}

            search_params = {k: v for k, v in params.items()
                    if v is not None and k not in exclude_params}
            
            hosts_response = await self.client.get_hosts(**search_params)
            hosts = hosts_response.get("results", [])
            total_count = hosts_response.get("count")

            if not hosts:
                return "No hosts found matching the specified criteria."
            
            if limit and len(hosts) > limit:
                hosts = hosts[:limit]
            
            # Format the response as a JSON string
            return json.dumps({"total_count": total_count, "hosts": hosts}, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch hosts: {str(e)}")
        
    async def get_host_details(
        self,
        host_id: Annotated[int, Field(description="ID of the host to retrieve details for", ge=1)]
    ):
        """
        Get complete detailed information about a specific host.
        
        Severity Level Logic:
        The severity level is calculated based on threat and certainty scores:
        - Critical: threat >= 50 AND certainty >= 50ß
        - High: threat >= 50 AND certainty < 50
        - Medium: threat < 50 AND certainty >= 50
        - Low: threat < 50 AND certainty < 50
        - Unknown: default fallback
        
        Returns:
            str: Formatted string with detailed information about the host. 
            If the host is not found, returns a message indicating that no host was found with the specified ID.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            host_details = await self.client.get_host(host_id)

            # Check if the host was found
            if 'detail' in host_details and host_details['detail'] == 'Not found.':
                return f"No host found with ID: {host_id}."
            
            return json.dumps(host_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch host details: {str(e)}")
    
    async def add_host_note(
        self,
        host_id: Annotated[
            int, Field(ge=1, description="ID of the host to add note to")
        ],
        note: Annotated[
            str, 
            Field(description="Note text to add to the host.")
        ]
    ) -> str:
        """
        Add an investigation note to a host.
        
        Returns:
            str: Confirmation message with note details.
        """
        try:
            create_note = await self.client.add_host_note(host_id, note)
            return json.dumps(create_note, indent=2)
        except Exception as e:
            raise Exception(f"Failed to add note to host {host_id}: {str(e)}")
    
    async def delete_host_note(
        self,
        host_id: Annotated[
            int, Field(ge=1, description="ID of the host to delete note from")
        ],
        note_id: Annotated[
            int, Field(ge=1, description="ID of the note to delete")
        ]
    ) -> str:
        """
        Delete a note from a host.
        
        Returns:
            str: Confirmation message.
        """
        try:
            delete_result = await self.client.delete_host_note(host_id, note_id)
            return json.dumps(delete_result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to delete note {note_id} from host {host_id}: {str(e)}")
    
    async def get_host_tags(
        self,
        host_id: Annotated[
            int, Field(ge=1, description="ID of the host to get tags for")
        ]
    ) -> str:
        """
        Get tags for a host.
        
        Returns:
            str: JSON string with host tags.
        """
        try:
            tags = await self.client.get_host_tags(host_id)
            return json.dumps(tags, indent=2)
        except Exception as e:
            raise Exception(f"Failed to get tags for host {host_id}: {str(e)}")
    
    async def update_host_tags(
        self,
        host_id: Annotated[
            int, Field(ge=1, description="ID of the host to update tags for")
        ],
        tags: Annotated[
            List[str], Field(description="List of tags to set for the host")
        ]
    ) -> str:
        """
        Update tags for a host.
        
        Returns:
            str: Confirmation message with updated tags.
        """
        try:
            update_result = await self.client.update_host_tags(host_id, tags)
            return json.dumps(update_result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to update tags for host {host_id}: {str(e)}")
