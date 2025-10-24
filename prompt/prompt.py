from typing import Optional, Literal, List, Dict, Any
from pydantic import Field

class VectraMCPPrompts:
    """Vectra AI MCP prompts for threat analysis and investigations."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_prompts(self):
        """Register all prompts with the MCP server."""
        self.vectra_mcp.prompt(
            name = "Summarize Detection",
            description = "Get a detailed summary of a specific detection in Vectra AI platform."
        )(self.summarize_detection)
        self.vectra_mcp.prompt(
            name = "Visualize Host Detections",
            description = "Visualize relationship of detections related to a specific host in Vectra AI platform with an interactive graph."
        )(self.visualize_host_detections)
        self.vectra_mcp.prompt(
            name = "Visualize Account Detections",
            description = "Visualize relationship of detections related to a specific account in Vectra AI platform with an interactive graph."
        )(self.visualize_account_detections)

    async def summarize_detection(
            self, 
            detection_id: int = Field(default= None, ge=1, le=999999, description="ID of the detection to summarize")
        ) -> str:
        """  
        Get a detailed summary of a specific detection in Vectra AI platform.
        
        Args:
            detection_id (int): The ID of the Vectra detection to summarize.
        
        Returns:
            str: A structured prompt for summarizing the detection.
            """
        return f"""
        Summarize the detection with detection_id : {detection_id}.
        Summarize the detection in a concise manner, focusing on key details such as the affected hosts/accounts, activity detected, targeted resources. 
        Return the summary in a structured table format, to facilitate easy understanding and further analysis.
        The summary table MUST include the following columns:
        - Detection ID
        - Threat Type
        - Affected Host/Account
        - Targeted Resources
        - Detection Time
        - Status
        - Assignment Status
        - Summary
        - Platform Links (Include direct links to the detection & host/account in the Vectra platform)

        Ensure that the summary is concise and actionable, providing insights into the nature of the threat and any immediate actions that may be required.

        DO NOT INCLUDE any additional information or context outside of the structured table format unless explicitly requested.
        """
    
    async def visualize_host_detections(
            self, 
            host_id: int = Field(default= None, description="ID of the host to visualize detections for", ge=1, le=999999),
            graph_theme: Optional[Literal['light', 'dark']] = Field(default="dark", description="Theme for the graph visualization")
        ) -> str:
        """  
        Visualize relationship of detections related to a specific host in Vectra AI platform with an interactive graph.
        
        Args:
            host_id (int): The ID of the host to visualize detections for.
            graph_theme (Optional[Literal['light', 'dark']]): Theme for the graph visualization
        
        Returns:
            str: A structured prompt for generating an interactive graph visualization of host detections.
            """
        return f"""
        Get all active detections on host : {host_id} and visualize the relationship of detections.
        Create an interactive graph that shows the connections between the host, its related detections and the targeted resources.
        The graph MUST include:
        - Nodes representing the host, its related detections and targeted resources
        - Edges representing the relationships between the host, detections and resources
        - Interactive features such as zooming, panning, and tooltips for additional information
        - Direct links within nodes to the host and related detections in the Vectra platform
        - Clear labels for each node and edge to provide context
        - A legend to explain different colors and shapes used in the graph
        - A clear title and description of the graph

        Ensure that the graph is clear, easy to understand, and visually appealing.
        Create the graph in {graph_theme} theme.
        """
    
    async def visualize_account_detections(
            self, 
            account_id: int = Field(default= None, description="ID of the account to visualize detections for", ge=1, le=999999),
            graph_theme: Optional[Literal['light', 'dark']] = Field(default="dark", description="Theme for the graph visualization")
        ) -> str:
        """  
        Visualize relationship of detections related to a specific account in Vectra AI platform with an interactive graph.
        
        Args:
            account_id (int): The ID of the account to visualize detections for.
            graph_theme (Optional[Literal['light', 'dark']]): Theme for the graph visualization
        
        Returns:
            str: A structured prompt for generating an interactive graph visualization of account detections.
            """
        return f"""
        Get all active detections on account : {account_id} and visualize the relationship of detections.
        Create an interactive graph that shows the connections between the account, its related detections and the targeted resources.
        The graph MUST include:
        - Nodes representing the account, its related detections and targeted resources
        - Edges representing the relationships between the account, detections and resources
        - Interactive features such as zooming, panning, and tooltips for additional information
        - Direct links within nodes to the account and related detections in the Vectra platform
        - Clear labels for each node and edge to provide context
        - A legend to explain different colors and shapes used in the graph
        - A clear title and description of the graph

        Ensure that the graph is clear, easy to understand, and visually appealing.
        Create the graph in {graph_theme} theme.
        """
