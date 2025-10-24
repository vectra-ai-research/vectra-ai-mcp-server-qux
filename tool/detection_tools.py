"""Detection analysis tools for security investigations on Vectra On-Premise."""

from typing import Literal, Annotated, List
from pydantic import Field, IPvAnyAddress
import json
import base64

from utils.validators import validate_date_range

class DetectionMCPTools:
    """MCP tools for detection analysis and management on Vectra On-Premise."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all detection tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_detection_ids)
        self.vectra_mcp.tool()(self.list_detections_with_basic_info)
        self.vectra_mcp.tool()(self.list_detections_with_details)
        self.vectra_mcp.tool()(self.get_detection_count)
        self.vectra_mcp.tool()(self.get_detection_details)
        self.vectra_mcp.tool()(self.get_detection_summary)
        self.vectra_mcp.tool()(self.get_detection_pcap)
        self.vectra_mcp.tool()(self.create_detection_note)
        self.vectra_mcp.tool()(self.get_detection_tags)
        self.vectra_mcp.tool()(self.update_detection_tags)
    
    async def get_detection_details(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve details for")
        ]
    ) -> str:
        """
        Get complete detailed information for a particular detection.
        
        Severity Level Logic:
        The severity level is calculated based on threat and certainty scores:
        - Critical: threat >= 50 AND certainty >= 50
        - High: threat >= 50 AND certainty < 50
        - Medium: threat < 50 AND certainty >= 50
        - Low: threat < 50 AND certainty < 50
        - Unknown: default fallback
        
        Returns:
            str: JSON string with detection details.

        Raises:
            Exception: If fetching detection details fails.
        """
        try:
            # Get detection details
            detection = await self.client.get_detection(detection_id)
            
            return json.dumps(detection)
        except Exception as e:
            raise Exception(f"Failed to retrieve details for detection {detection_id}: {str(e)}")

    async def list_detections_with_details(
        self,
        ordering: Annotated[
            str, 
            Field(description="Order by field name. Use '-' prefix for descending order (e.g., '-last_timestamp', 'id')")
        ] = "-last_timestamp",
        category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category (alternative parameter)")
        ] = None,
        detection_type: Annotated[
            str | None, 
            Field(description="Filter by detection type/name. Can also perform partial word match")
        ] = None,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection. Must be a valid IPv4 or IPv6 address.")
        ] = None,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False,
        limit: Annotated[
            int, 
            Field(description="Maximum number of detections to return in the batch. Defaults to 1000", ge = 1, le=1000)
        ] = 1000
    )-> str:
        """
        List detections with basic filtering and sorting options.

        This tool provides basic filtering capabilities for detections. For advanced searches
        (e.g., specific detection types, source IPs, source hosts, sensor names, 
        detection descriptions, or complex queries), use the advanced_search_detections tool instead.

        Basic filters supported:
        - ordering: sort by last_timestamp, id, etc.
        - category: detection category (command, botnet, lateral, reconnaissance, exfiltration, info)
        - detection_type: partial detection type matching
        - state: detection state (active, inactive, fixed, filteredbyai, filteredbyrule)
        - threat_gte: minimum threat score
        - certainty_gte: minimum certainty score
        - date ranges: last_timestamp filtering

        For specific searches like:
        - Finding detections by exact type: use advanced_search_detections
        - Finding detections by source IP: use advanced_search_detections
        - Finding detections by source host: use advanced_search_detections
        - Finding detections by sensor name: use advanced_search_detections
        - Finding detections with specific descriptions: use advanced_search_detections
        - Complex boolean queries: use advanced_search_detections

        Returns:
            str: JSON string with list of detections.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_type'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_type:
            search_params['detection_type'] = detection_type
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."

        response = {"detection_count": total_count, "detections": detections}
        
        if limit:
            if total_count > limit:
            # Limit the number of detections returned to reduce response size
                detections = detections[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections"] = detections
            
        return json.dumps(response, indent=2)

    async def get_detection_count(
        self,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category")
        ] = None,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active' which returns only currently active detections.")
        ] = "active",
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection.")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False
    ) -> str:
        """
        Get the total count of detections matching the specified criteria.

        Returns:
            str: Count of detections matching the criteria.
        """
        params = locals().copy()
        exclude_params = {'self', 'start_date', 'end_date'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        # Add date filters if provided
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        detections_response = await self.client.get_detections(**search_params)
        total_count = detections_response.get("count")
        
        return f"Total detections matching criteria: {total_count}"
    
    async def get_detection_pcap(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve pcap for")
        ]
    ) -> str:
        """
        Get pcap file for a specific detection.
        
        Returns:
            str: Base64 encoded pcap data or error message.

        Raises:
            Exception: If retrieval fails.
        """
        try:
            pcap_data = await self.client.get_detection_pcap(detection_id)

            if not pcap_data:
                return f"No pcap data found for detection ID {detection_id}."
            
            # Encode binary content as base64
            encoded_content = base64.b64encode(pcap_data).decode('utf-8')

            return f"PCAP data for detection ID {detection_id}:\n{encoded_content}"

        except Exception as e:
            raise Exception(f"Failed to retrieve pcap for detection {detection_id}: {str(e)}")
        
    async def list_detections_with_basic_info(
        self,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        ordering: Annotated[
            Literal['created_datetime', 'last_timestamp', 'id'] | None, 
            Field(description="Order by last_timestamp, created_datetime, or id. Defaults to 'last_timestamp'")
        ] = "last_timestamp",
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection")
        ] = None,
        start_date: Annotated[str | None, Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")] = None,
        end_date: Annotated[str | None, Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")] = None,
        is_targeting_key_asset: Annotated[bool, Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")] = False,
        limit: Annotated[int, Field(description="Maximum number of detections to return in the batch.", ge = 1, le=1000)] = None
    )-> str:
        """
        List detections with basic information and minimal filtering options.

        This tool provides very basic filtering capabilities for detections. For advanced searches
        (e.g., specific detection types, source IPs, source hosts, sensor names, 
        detection descriptions, or complex queries), use the advanced_search_detections tool instead.

        Basic filters supported:
        - state: detection state (active, inactive, fixed, filteredbyai, filteredbyrule)
        - ordering: sort by created_datetime, last_timestamp, or id
        - detection_category: detection category filtering
        - detection_name: partial detection name matching
        - date ranges: timestamp filtering

        For specific searches like:
        - Finding detections by exact type: use advanced_search_detections
        - Finding detections by source IP: use advanced_search_detections
        - Finding detections by source host: use advanced_search_detections
        - Finding detections by sensor name: use advanced_search_detections
        - Finding detections with specific descriptions: use advanced_search_detections
        - Complex boolean queries: use advanced_search_detections
        
        Returns:
            str: JSON string with list of detections ids.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_name'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_name:
            search_params['detection_type'] = detection_name
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."
        
        detection_list = [
                {
                    'id': dets['id'], 
                    'name': dets['detection'],
                    'detection_category': dets['detection_category'],
                    'last_timestamp': dets['last_timestamp'],
                    'is_triaged': dets.get('is_triaged'),
                    'state': dets.get('state', 'unknown'),
                    'entity_type': dets.get('type', 'unknown')
                }
                for dets in detections
            ]

        response = {"detection_count": total_count, "detections": detection_list}
        
        if limit:
            if total_count > limit:
            # Limit the number of detections returned to reduce response size
                detections = detections[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections"] = detection_list
            
        return json.dumps(response, indent=2)
    
    async def get_detection_summary(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve summary for")
        ]
    ) -> str:
        """
        Get a concise summary of a detection including its ID, name, category, last timestamp, triage status, state, entity type, and detection summary. The detection summary includes key details about the detection including event specific details and description.
        
        Returns:
            str: Formatted string with detection summary.
        """
        try:
            detection = await self.client.get_detection(detection_id)
            if not detection:
                return f"Detection with ID {detection_id} not found."
            
            detection_summary = {
                "id": detection.get("id"),
                "name": detection.get("detection"),
                "category": detection.get("detection_category", detection.get("category")),
                "last_timestamp": detection.get("last_timestamp"),
                "is_triaged": detection.get("is_triaged"),
                "state": detection.get("state", "unknown"),
                "entity_type": detection.get("type", "unknown"),
                "detection_summary": detection.get("summary", "No summary available"),
            }
            
            return json.dumps(detection_summary, indent=2)
        
        except Exception as e:
            raise Exception(f"Failed to retrieve detection summary: {str(e)}")
        
    async def list_detection_ids(
        self,
        ordering: Annotated[
            Literal['created_datetime', 'last_timestamp', 'id'] | None, 
            Field(description="Order by last_timestamp, created_datetime, or id")
        ] = "last_timestamp",
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection")
        ] = None,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False,
        limit: Annotated[
            int, 
            Field(description="Maximum number of detections to return in the batch. Defaults to 1000.", ge = 1, le=1000)
        ] = 1000
    )-> str:
        """
        List detection IDs with filtering and sorting options. Use this to get a list of detection IDs based on various criteria.

        Returns:
            str: JSON string with list of detection IDs.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_name'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_name:
            search_params['detection_type'] = detection_name
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."
        
        # Extract only detection IDs
        detection_ids = [
            {
                'id': dets['id']
            }
            for dets in detections
        ]

        response = {"detection_count": total_count, "detections_ids": detection_ids}
        
        if limit:
            if total_count > limit:
            # Limit the number of detection IDs returned to reduce response size
                detection_ids = detection_ids[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections_ids"] = detection_ids
            
        return json.dumps(response, indent=2)
    
    async def create_detection_note(
        self,
        detection_id: Annotated[
            int, Field(ge=1, description="ID of the detection to add note to")
        ],
        note: Annotated[
            str, 
            Field(description="Note text to add to the detection.")
        ]
    ) -> str:
        """
        Add an investigation note to a detection.
        
        Returns:
            str: Confirmation message with note details.
        """
        try:
            create_note = await self.client.add_detection_note(detection_id, note)
            return json.dumps(create_note, indent=2)
        except Exception as e:
            raise Exception(f"Failed to add note to detection {detection_id}: {str(e)}")
    
    async def get_detection_tags(
        self,
        detection_id: Annotated[
            int, Field(ge=1, description="ID of the detection to get tags for")
        ]
    ) -> str:
        """
        Get tags for a detection.
        
        Returns:
            str: JSON string with detection tags.
        """
        try:
            tags = await self.client.get_detection_tags(detection_id)
            return json.dumps(tags, indent=2)
        except Exception as e:
            raise Exception(f"Failed to get tags for detection {detection_id}: {str(e)}")
    
    async def update_detection_tags(
        self,
        detection_id: Annotated[
            int, Field(ge=1, description="ID of the detection to update tags for")
        ],
        tags: Annotated[
            List[str], 
            Field(description="List of tags to set for the detection")
        ]
    ) -> str:
        """
        Update tags for a detection.
        
        Returns:
            str: Confirmation message with updated tags.
        """
        try:
            updated_tags = await self.client.update_detection_tags(detection_id, tags)
            return json.dumps(updated_tags, indent=2)
        except Exception as e:
            raise Exception(f"Failed to update tags for detection {detection_id}: {str(e)}")