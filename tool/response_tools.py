"""MCP tools for response actions on Vectra On-Premise."""

import json

class ResponseMCPTools:
    """MCP tools for response actions on Vectra On-Premise."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all response tools with the MCP server."""
        # Note: On-premise API doesn't have lockdown functionality
        # This class is kept for future response tools
        pass