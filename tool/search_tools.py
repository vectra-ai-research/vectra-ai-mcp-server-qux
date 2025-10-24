"""MCP tools for advanced search functionality on Vectra On-Premise."""

import json
from typing import Annotated, Literal, Optional, List, Dict, Any
from pydantic import Field

from utils.validators import validate_date_range


class AdvancedSearchMCPTools:
    """MCP tools for advanced search functionality on Vectra On-Premise."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all advanced search tools with the MCP server."""
        self.vectra_mcp.tool()(self.advanced_search_accounts)
        self.vectra_mcp.tool()(self.advanced_search_hosts)
        self.vectra_mcp.tool()(self.advanced_search_detections)
        self.vectra_mcp.tool()(self.unified_search)
    
    async def advanced_search_accounts(
        self,
        query_string: Annotated[
            str,
            Field(description="Lucene search query for accounts. Use field:value syntax (e.g., 'account.name:admin*', 'account.ldap.department:IT', 'account.privilege_level:[8 TO 10]'). For complete field reference and examples, refer to vectra://search/account-fields and vectra://search/query-examples resources.")
        ],
        page: Annotated[
            int | None,
            Field(description="Page number for pagination (default: 1)", ge=1)
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Number of results per page (default: 50, max: 5000)", ge=1, le=5000)
        ] = None,
        auto_paginate: Annotated[
            bool,
            Field(description="Automatically paginate through all results (default: False)")
        ] = False
    ) -> str:
        """
        Advanced search for accounts using Lucene query syntax.
        
        USE THIS TOOL FOR SPECIFIC ACCOUNT SEARCHES:
        - Finding accounts by name: account.name:admin*
        - Finding accounts by privilege level: account.privilege_level:[8 TO 10]
        - Finding accounts by department: account.ldap.department:IT
        - Finding accounts with expired passwords: account.ldap.password_expired:true
        - Finding accounts with high-threat detections: account.detection_summaries.threat:[80 TO 99]
        - Finding accounts with many file downloads: account.detection_summaries.summary.files_downloaded:[100 TO *]
        - Finding accounts with disabled MFA: account.detection_summaries.summary.mfa_status:disabled
        - Finding accounts in specific groups: account.ldap.member_of:*Domain Admins*
        - Complex boolean queries: account.ldap.password_expired:true AND account.privilege_level:[8 TO 10]
        
        This tool provides powerful search capabilities for accounts using Lucene query syntax.
        You can search by any account field, use ranges, wildcards, and boolean operators.
        
        IMPORTANT: For comprehensive field reference, query examples, and best practices, 
        refer to the MCP resources:
        - vectra://search/account-fields: Complete list of all account fields from Advanced_Search_Accounts.md
        - vectra://search/query-examples: Practical query examples and syntax
        - vectra://search/advanced-guide: Best practices and troubleshooting tips
        
        Examples:
        - account.name:admin* (accounts with names starting with 'admin')
        - account.privilege_level:[8 TO 10] (accounts with high privilege levels)
        - account.ldap.department:IT (accounts in IT department)
        - account.ldap.password_expired:true (accounts with expired passwords)
        - account.detection_summaries.threat:[80 TO 99] (accounts with high-threat detections)
        - account.detection_summaries.summary.files_downloaded:[100 TO *] (accounts with many file downloads)
        - account.detection_summaries.summary.mfa_status:disabled (accounts with disabled MFA)
        - account.ldap.member_of:*Domain Admins* (accounts in Domain Admins group)
        
        Returns:
            str: JSON string with search results including accounts and metadata.
        """
        try:
            params = {k: v for k, v in {
                "query_string": query_string,
                "page": page,
                "page_size": page_size,
            }.items() if v is not None}
            
            if auto_paginate:
                results = await self.client._get_all_pages("search/accounts", params)
            else:
                results = await self.client.search_accounts(**params)
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to search accounts: {str(e)}")
    
    async def advanced_search_hosts(
        self,
        query_string: Annotated[
            str,
            Field(description="Lucene search query for hosts. Use field:value syntax (e.g., 'host.name:server*', 'host.ip:192.168.1.*', 'host.is_key_asset:true'). For complete field reference and examples, refer to vectra://search/host-fields and vectra://search/query-examples resources.")
        ],
        page: Annotated[
            int | None,
            Field(description="Page number for pagination (default: 1)", ge=1)
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Number of results per page (default: 50, max: 5000)", ge=1, le=5000)
        ] = None,
        auto_paginate: Annotated[
            bool,
            Field(description="Automatically paginate through all results (default: False)")
        ] = False
    ) -> str:
        """
        Advanced search for hosts using Lucene query syntax.
        
        USE THIS TOOL FOR SPECIFIC HOST SEARCHES:
        - Finding hosts by name: host.name:server*
        - Finding hosts by IP address: host.ip:192.168.1.*
        - Finding key asset hosts: host.is_key_asset:true
        - Finding hosts with high-threat detections: host.detection_summaries.threat:[80 TO 99]
        - Finding hosts with high data transfer: host.detection_summaries.summary.bytes_sent:[1000000 TO *]
        - Finding hosts with beaconing behavior: host.detection_summaries.summary.beaconing:[10 TO *]
        - Finding hosts that contacted dark IPs: host.detection_summaries.summary.dark_ips_contacted:*
        - Finding hosts by sensor: host.sensor_name:DMZ*
        - Complex boolean queries: host.is_key_asset:true AND host.detection_summaries.threat:[80 TO 99]
        
        This tool provides powerful search capabilities for hosts using Lucene query syntax.
        You can search by any host field, use ranges, wildcards, and boolean operators.
        
        IMPORTANT: For comprehensive field reference, query examples, and best practices, 
        refer to the MCP resources:
        - vectra://search/host-fields: Complete list of all host fields from Advanced_Search_Hosts.md
        - vectra://search/query-examples: Practical query examples and syntax
        - vectra://search/advanced-guide: Best practices and troubleshooting tips
        
        Examples:
        - host.name:server* (hosts with names starting with 'server')
        - host.ip:192.168.1.* (hosts in 192.168.1.x subnet)
        - host.is_key_asset:true (key asset hosts)
        - host.detection_summaries.threat:[80 TO 99] (hosts with high-threat detections)
        - host.detection_summaries.summary.bytes_sent:[1000000 TO *] (hosts with high data transfer)
        - host.detection_summaries.summary.beaconing:[10 TO *] (hosts with beaconing behavior)
        - host.detection_summaries.summary.dark_ips_contacted:* (hosts that contacted dark IPs)
        - host.sensor_name:DMZ* (hosts detected by DMZ sensors)
        
        Returns:
            str: JSON string with search results including hosts and metadata.
        """
        try:
            params = {k: v for k, v in {
                "query_string": query_string,
                "page": page,
                "page_size": page_size,
            }.items() if v is not None}
            
            if auto_paginate:
                results = await self.client._get_all_pages("search/hosts", params)
            else:
                results = await self.client.search_hosts(**params)
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to search hosts: {str(e)}")
    
    async def advanced_search_detections(
        self,
        query_string: Annotated[
            str,
            Field(description="Lucene search query for detections. Use field:value syntax (e.g., 'detection.category:lateral', 'detection.grouped_details.src_ip:192.168.1.100', 'detection.grouped_details.file_extension:exe'). For complete field reference and examples, refer to vectra://search/detection-fields and vectra://search/query-examples resources.")
        ],
        page: Annotated[
            int | None,
            Field(description="Page number for pagination (default: 1)", ge=1)
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Number of results per page (default: 50, max: 5000)", ge=1, le=5000)
        ] = None,
        auto_paginate: Annotated[
            bool,
            Field(description="Automatically paginate through all results (default: False)")
        ] = False
    ) -> str:
        """
        Advanced search for detections using Lucene query syntax.
        
        USE THIS TOOL FOR SPECIFIC DETECTION SEARCHES:
        - Finding detections by category: detection.category:lateral
        - Finding detections by source IP: detection.grouped_details.src_ip:192.168.1.100
        - Finding detections by file type: detection.grouped_details.file_extension:exe
        - Finding detections by data transfer: detection.grouped_details.bytes_sent:[1000000 TO *]
        - Finding detections by privilege level: detection.src_account.privilege_level:[8 TO 10]
        - Finding detections by URL patterns: detection.grouped_details.url:*malicious*
        - Finding detections by user agent: detection.grouped_details.user_agent:*bot*
        - Finding detections with encrypted files: detection.grouped_details.encrypted_file_count:[10 TO *]
        - Complex boolean queries: detection.category:lateral AND detection.grouped_details.src_ip:192.168.1.*
        
        This tool provides powerful search capabilities for detections using Lucene query syntax.
        You can search by any detection field, use ranges, wildcards, and boolean operators.
        
        IMPORTANT: For comprehensive field reference, query examples, and best practices, 
        refer to the MCP resources:
        - vectra://search/detection-fields: Complete list of all detection fields from Advanced_Search_Detections.md
        - vectra://search/query-examples: Practical query examples and syntax
        - vectra://search/advanced-guide: Best practices and troubleshooting tips
        
        Examples:
        - detection.category:lateral (lateral movement detections)
        - detection.grouped_details.src_ip:192.168.1.100 (detections from specific IP)
        - detection.is_targeting_key_asset:true AND detection.threat:[80 TO *] (high threat detections targeting key assets)
        - detection.grouped_details.file_extension:exe (detections involving executable files)
        - detection.grouped_details.bytes_sent:[1000000 TO *] (detections with high data transfer)
        - detection.src_account.privilege_level:[8 TO 10] (detections from high-privilege accounts)
        - detection.grouped_details.url:*malicious* (detections involving malicious URLs)
        - detection.grouped_details.user_agent:*bot* (detections with bot user agents)
        - detection.grouped_details.encrypted_file_count:[10 TO *] (detections with many encrypted files)
        
        Returns:
            str: JSON string with search results including detections and metadata.
        """
        try:
            params = {k: v for k, v in {
                "query_string": query_string,
                "page": page,
                "page_size": page_size,
            }.items() if v is not None}
            
            if auto_paginate:
                results = await self.client._get_all_pages("search/detections", params)
            else:
                results = await self.client.search_detections(**params)
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to search detections: {str(e)}")
    
    async def unified_search(
        self,
        query_string: Annotated[
            str,
            Field(description="Lucene search query to search across accounts, hosts, and detections. Use field:value syntax with entity-specific fields. For complete field reference and examples, refer to vectra://search/account-fields, vectra://search/host-fields, vectra://search/detection-fields, and vectra://search/query-examples resources.")
        ],
        entity_types: Annotated[
            List[Literal["accounts", "hosts", "detections"]],
            Field(description="List of entity types to search (default: all types)")
        ] = ["accounts", "hosts", "detections"],
        page: Annotated[
            int | None,
            Field(description="Page number for pagination (default: 1)", ge=1)
        ] = None,
        page_size: Annotated[
            int | None,
            Field(description="Number of results per page (default: 50, max: 5000)", ge=1, le=5000)
        ] = None,
        auto_paginate: Annotated[
            bool,
            Field(description="Automatically paginate through all results (default: False)")
        ] = False
    ) -> str:
        """
        Unified search across multiple entity types using Lucene query syntax.
        
        This tool allows you to search across accounts, hosts, and detections simultaneously
        using a single query string. Results are organized by entity type.
        
        IMPORTANT: For comprehensive field reference, query examples, and best practices, 
        refer to the MCP resources:
        - vectra://search/account-fields: Complete list of all account fields
        - vectra://search/host-fields: Complete list of all host fields
        - vectra://search/detection-fields: Complete list of all detection fields
        - vectra://search/query-examples: Practical query examples and syntax
        - vectra://search/advanced-guide: Best practices and troubleshooting tips
        
        Examples:
        - name:admin* (search for entities with names starting with 'admin')
        - threat:[80 TO 99] (search for entities with threat scores 80-99)
        - state:active AND tags:critical (search for active entities tagged as critical)
        - last_detection_timestamp:[2024-01-01T00:00:00Z TO *] (search for entities with recent detections)
        
        Returns:
            str: JSON string with search results organized by entity type.
        """
        try:
            results = {}
            params = {k: v for k, v in {
                "page": page,
                "page_size": page_size,
            }.items() if v is not None}
            
            # Search each requested entity type
            for entity_type in entity_types:
                try:
                    if entity_type == "accounts":
                        if auto_paginate:
                            entity_results = await self.client._get_all_pages("search/accounts", {"query_string": query_string, **params})
                        else:
                            entity_results = await self.client.search_accounts(query_string=query_string, **params)
                    elif entity_type == "hosts":
                        if auto_paginate:
                            entity_results = await self.client._get_all_pages("search/hosts", {"query_string": query_string, **params})
                        else:
                            entity_results = await self.client.search_hosts(query_string=query_string, **params)
                    elif entity_type == "detections":
                        if auto_paginate:
                            entity_results = await self.client._get_all_pages("search/detections", {"query_string": query_string, **params})
                        else:
                            entity_results = await self.client.search_detections(query_string=query_string, **params)
                    
                    results[entity_type] = entity_results
                    
                except Exception as e:
                    results[entity_type] = {"error": f"Failed to search {entity_type}: {str(e)}"}
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to perform unified search: {str(e)}")
