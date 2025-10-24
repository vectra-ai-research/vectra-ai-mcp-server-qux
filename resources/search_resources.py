"""MCP resources for Vectra On-Premise search query guidance."""

import json
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


class VectraSearchResources:
    """Resources providing guidance on Vectra On-Premise search capabilities."""
    
    def __init__(self, vectra_mcp: FastMCP):
        """Initialize with FastMCP instance.
        
        Args:
            vectra_mcp: FastMCP server instance
        """
        self.vectra_mcp = vectra_mcp
    
    def register_resources(self):
        """Register all search guidance resources with the MCP server."""
        # Register resources
        self.vectra_mcp.resource("vectra://search/query-examples")(self.get_lucene_query_examples)
        self.vectra_mcp.resource("vectra://search/advanced-guide")(self.get_advanced_search_guide)
        self.vectra_mcp.resource("vectra://search/detection-fields")(self.get_detection_fields_reference)
        self.vectra_mcp.resource("vectra://search/account-fields")(self.get_account_fields_reference)
        self.vectra_mcp.resource("vectra://search/host-fields")(self.get_host_fields_reference)
        
        # Register the read_resource tool so Claude can access resources
        self.vectra_mcp.tool()(self.read_resource)
    
    
    async def get_lucene_query_examples(self) -> str:
        """
        Comprehensive examples of Lucene query syntax for Vectra On-Premise search.
        
        This resource provides practical examples of how to construct effective
        search queries using Lucene syntax.
        """
        content = {
            "title": "Vectra On-Premise Lucene Query Examples",
            "description": "Practical examples of Lucene query syntax for advanced search",
            "basic_queries": {
                "description": "Basic field-value searches",
                "examples": [
                    {
                        "query": "name:admin",
                        "description": "Find entities with name containing 'admin'"
                    },
                    {
                        "query": "state:active",
                        "description": "Find active entities"
                    },
                    {
                        "query": "threat:85",
                        "description": "Find entities with threat score of 85"
                    },
                    {
                        "query": "is_key_asset:true",
                        "description": "Find key assets"
                    }
                ]
            },
            "quoted_vs_wildcard_examples": {
                "title": "Quoted Strings vs Wildcards - Practical Examples",
                "description": "Real-world examples showing when to use quotes vs wildcards",
                "detection_examples": [
                    {
                        "scenario": "Searching for specific detection name",
                        "exact_quotes": "detection_type:\"Add service principal credentials\"",
                        "description": "Matches exact detection name (most reliable)"
                    },
                    {
                        "scenario": "Searching for detections starting with specific text",
                        "prefix_wildcard": "detection_type:Add service principal credential*",
                        "description": "Matches detections starting with this text (reliable)"
                    },
                    {
                        "scenario": "Searching for detections ending with specific text",
                        "suffix_wildcard": "detection_type:*service principal credentials",
                        "description": "Matches detections ending with this text (less reliable)"
                    }
                ],
                "group_examples": [
                    {
                        "scenario": "Searching for exact group name",
                        "exact_quotes": "account.ldap.member_of:\"Domain Admins\"",
                        "description": "Matches exact group name (most reliable)"
                    },
                    {
                        "scenario": "Searching for groups starting with specific text",
                        "prefix_wildcard": "account.ldap.member_of:Domain Admins*",
                        "description": "Matches groups starting with 'Domain Admins' (reliable)"
                    },
                    {
                        "scenario": "Searching for groups ending with specific text",
                        "suffix_wildcard": "account.ldap.member_of:*Admins",
                        "description": "Matches groups ending with 'Admins' (less reliable)"
                    }
                ],
                "os_examples": [
                    {
                        "scenario": "Searching for exact OS name",
                        "exact_quotes": "host.ldap.operating_system:\"Windows Server 2019\"",
                        "description": "Matches exact OS name (most reliable)"
                    },
                    {
                        "scenario": "Searching for OS starting with specific text",
                        "prefix_wildcard": "host.ldap.operating_system:Windows*",
                        "description": "Matches OS starting with 'Windows' (reliable)"
                    }
                ]
            },
            "wildcard_queries": {
                "description": "Using wildcards for pattern matching - CRITICAL: Use prefix wildcards for best results",
                "examples": [
                    {
                        "query": "name:server*",
                        "description": "Find entities with names starting with 'server' (PREFIX wildcard - reliable)"
                    },
                    {
                        "query": "ip:192.168.1.*",
                        "description": "Find hosts in 192.168.1.x subnet (PREFIX wildcard - reliable)"
                    },
                    {
                        "query": "detection_type:ransomware*",
                        "description": "Find detections with types starting with 'ransomware' (PREFIX wildcard - reliable)"
                    },
                    {
                        "query": "detection_type:*ransomware",
                        "description": "Find detections with types ending with 'ransomware' (SUFFIX wildcard - less reliable)"
                    },
                    {
                        "query": "sensor_name:DMZ*",
                        "description": "Find entities detected by sensors starting with 'DMZ' (PREFIX wildcard - reliable)"
                    },
                    {
                        "query": "account.ldap.member_of:Domain Admins*",
                        "description": "Find accounts in groups starting with 'Domain Admins' (PREFIX wildcard - reliable)"
                    }
                ],
                "wildcard_warnings": [
                    "⚠️ SUFFIX wildcards (*text) often fail to match",
                    "✅ PREFIX wildcards (text*) work reliably",
                    "✅ EXACT matches work best when possible",
                    "🔄 Try progressive strategy: exact → prefix → suffix → both"
                ]
            },
            "range_queries": {
                "description": "Using ranges for numeric and date fields",
                "examples": [
                    {
                        "query": "threat:[80 TO 99]",
                        "description": "Find entities with threat scores between 80-99"
                    },
                    {
                        "query": "certainty:[70 TO *]",
                        "description": "Find entities with certainty score >= 70"
                    },
                    {
                        "query": "privilege_level:[8 TO 10]",
                        "description": "Find accounts with privilege level 8-10"
                    },
                    {
                        "query": "last_detection_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find entities with detections since January 1, 2024"
                    },
                    {
                        "query": "created_timestamp:[2024-01-01T00:00:00Z TO 2024-01-31T23:59:59Z]",
                        "description": "Find detections created in January 2024"
                    }
                ]
            },
            "boolean_queries": {
                "description": "Using boolean operators (AND, OR, NOT)",
                "examples": [
                    {
                        "query": "state:active AND threat:[50 TO *]",
                        "description": "Find active entities with threat >= 50"
                    },
                    {
                        "query": "is_key_asset:true AND threat:[70 TO 99]",
                        "description": "Find key assets with high threat scores"
                    },
                    {
                        "query": "tags:critical OR tags:high-priority",
                        "description": "Find entities tagged as critical or high-priority"
                    },
                    {
                        "query": "category:lateral AND is_targeting_key_asset:true",
                        "description": "Find lateral movement detections targeting key assets"
                    },
                    {
                        "query": "state:active AND NOT tags:false-positive",
                        "description": "Find active entities not tagged as false positives"
                    }
                ]
            },
            "complex_queries": {
                "description": "Complex queries combining multiple conditions",
                "examples": [
                    {
                        "query": "(state:active AND threat:[70 TO *]) AND (tags:critical OR tags:investigation)",
                        "description": "Find active high-threat entities tagged for investigation"
                    },
                    {
                        "query": "sensor_name:DMZ* AND category:(lateral OR exfiltration)",
                        "description": "Find DMZ sensor detections of lateral movement or exfiltration"
                    },
                    {
                        "query": "last_detection_timestamp:[2024-01-01T00:00:00Z TO *] AND (is_key_asset:true OR is_targeting_key_asset:true)",
                        "description": "Find entities with recent detections involving key assets"
                    },
                    {
                        "query": "privilege_level:[8 TO 10] AND account_type:kerberos AND state:active",
                        "description": "Find active Kerberos accounts with high privilege levels"
                    }
                ]
            },
            "comparison_operator_examples": {
                "title": "🔢 Comparison Operator Examples",
                "description": "Practical examples using comparison operators for numeric and date fields",
                "numeric_examples": [
                    {
                        "query": "detection.grouped_details.bytes_sent:>1000000",
                        "description": "Find detections with more than 1MB data transfer"
                    },
                    {
                        "query": "detection.grouped_details.bytes_received:>=500000",
                        "description": "Find detections with at least 500KB data received"
                    },
                    {
                        "query": "detection.grouped_details.file_count:<100",
                        "description": "Find detections with fewer than 100 files"
                    },
                    {
                        "query": "detection.grouped_details.encrypted_file_count:>10",
                        "description": "Find detections with more than 10 encrypted files"
                    },
                    {
                        "query": "host.threat:>80",
                        "description": "Find hosts with threat score greater than 80"
                    },
                    {
                        "query": "host.certainty:>=70",
                        "description": "Find hosts with certainty score of 70 or higher"
                    },
                    {
                        "query": "detection.certainty:<50",
                        "description": "Find detections with certainty score less than 50"
                    }
                ],
                "date_examples": [
                    {
                        "query": "detection.created_timestamp:>2024-01-01T00:00:00Z",
                        "description": "Find detections created after January 1, 2024"
                    },
                    {
                        "query": "detection.first_timestamp:>=2024-01-01T00:00:00Z",
                        "description": "Find detections with first activity on or after January 1, 2024"
                    },
                    {
                        "query": "detection.last_timestamp:<2024-12-31T23:59:59Z",
                        "description": "Find detections with last activity before December 31, 2024"
                    },
                    {
                        "query": "host.last_detection_timestamp:<=2024-01-01T00:00:00Z",
                        "description": "Find hosts with last detection on or before January 1, 2024"
                    }
                ],
                "count_examples": [
                    {
                        "query": "detection.grouped_details.num_attempts:>5",
                        "description": "Find detections with more than 5 attempts"
                    },
                    {
                        "query": "detection.grouped_details.num_successes:>=10",
                        "description": "Find detections with at least 10 successes"
                    },
                    {
                        "query": "detection.grouped_details.num_events:<100",
                        "description": "Find detections with fewer than 100 events"
                    },
                    {
                        "query": "detection.grouped_details.num_matches:<=50",
                        "description": "Find detections with at most 50 matches"
                    }
                ],
                "combined_examples": [
                    {
                        "query": "detection.grouped_details.bytes_sent:>1000000 AND detection.category:exfiltration",
                        "description": "Find exfiltration detections with high data transfer"
                    },
                    {
                        "query": "host.threat:>80 AND host.state:active",
                        "description": "Find active hosts with high threat scores"
                    },
                    {
                        "query": "detection.created_timestamp:>2024-01-01T00:00:00Z AND detection.certainty:>=80",
                        "description": "Find recent high-certainty detections"
                    },
                    {
                        "query": "detection.grouped_details.num_attempts:>10 AND detection.grouped_details.num_successes:<5",
                        "description": "Find detections with many attempts but few successes"
                    }
                ]
            },
            "field_specific_examples": {
                "accounts": [
                    "name:admin* AND privilege_level:[8 TO 10]",
                    "state:active AND threat:[80 TO 99] AND tags:critical",
                    "account_type:o365 AND last_detection_timestamp:[2024-01-01T00:00:00Z TO *]"
                ],
                "hosts": [
                    "ip:192.168.1.* AND is_key_asset:true",
                    "name:server* AND sensor_name:DMZ* AND threat:[70 TO *]",
                    "state:active AND certainty:[80 TO 99] AND tags:production"
                ],
                "detections": [
                    "category:lateral AND src_ip:192.168.1.100",
                    "is_targeting_key_asset:true AND threat:[80 TO 99] AND state:active",
                    "detection_type:*ransomware* AND created_timestamp:[2024-01-01T00:00:00Z TO *]"
                ]
            }
        }
        
        return json.dumps(content, indent=2)
    
    async def get_advanced_search_guide(self) -> str:
        """
        Advanced search guide with best practices and tips for Vectra On-Premise.
        
        This resource provides guidance on constructing effective search queries
        and understanding search behavior.
        """
        content = {
            "title": "Vectra On-Premise Advanced Search Guide",
            "description": "Best practices and tips for effective search queries",
            "search_syntax": {
                "description": "Lucene query syntax rules",
                "rules": [
                    "Field names are case-sensitive",
                    "Use quotes for EXACT phrase matches: \"Add service principal credentials\"",
                    "Use wildcards * and ? for pattern matching (without quotes)",
                    "Use square brackets for ranges: [80 TO 99]",
                    "Use parentheses for grouping: (condition1 OR condition2) AND condition3",
                    "Boolean operators: AND, OR, NOT (must be uppercase)",
                    "Use + and - for required and prohibited terms: +required -prohibited"
                ]
            },
            "comparison_operators": {
                "title": "Comparison Operators for Numeric and Date Fields",
                "description": "Use comparison operators for numeric and date field queries",
                "operators": {
                    ":": {
                        "description": "Equals (exact match)",
                        "syntax": "field:value",
                        "examples": [
                            "detection.grouped_details.bytes_sent:1000",
                            "host.threat:85",
                            "detection.certainty:90"
                        ]
                    },
                    ":>": {
                        "description": "Greater than",
                        "syntax": "field:>value",
                        "examples": [
                            "detection.grouped_details.bytes_sent:>1000",
                            "host.threat:>80",
                            "detection.certainty:>70"
                        ]
                    },
                    ":>=": {
                        "description": "Greater than or equal to",
                        "syntax": "field:>=value",
                        "examples": [
                            "detection.grouped_details.bytes_sent:>=1000",
                            "host.threat:>=80",
                            "detection.certainty:>=70"
                        ]
                    },
                    ":<": {
                        "description": "Less than",
                        "syntax": "field:<value",
                        "examples": [
                            "detection.grouped_details.bytes_sent:<5000",
                            "host.threat:<50",
                            "detection.certainty:<30"
                        ]
                    },
                    ":<=": {
                        "description": "Less than or equal to",
                        "syntax": "field:<=value",
                        "examples": [
                            "detection.grouped_details.bytes_sent:<=5000",
                            "host.threat:<=50",
                            "detection.certainty:<=30"
                        ]
                    }
                },
                "field_types": {
                    "numeric_fields": {
                        "description": "Use comparison operators with numeric fields",
                        "examples": [
                            "detection.grouped_details.bytes_sent:>1000000",
                            "detection.grouped_details.bytes_received:>=500000",
                            "detection.grouped_details.file_count:<100",
                            "detection.grouped_details.encrypted_file_count:>10",
                            "host.threat:>80",
                            "host.certainty:>=70",
                            "detection.certainty:<50"
                        ]
                    },
                    "date_fields": {
                        "description": "Use comparison operators with date fields",
                        "examples": [
                            "detection.created_timestamp:>2024-01-01T00:00:00Z",
                            "detection.first_timestamp:>=2024-01-01T00:00:00Z",
                            "detection.last_timestamp:<2024-12-31T23:59:59Z",
                            "host.last_detection_timestamp:<=2024-01-01T00:00:00Z"
                        ]
                    },
                    "count_fields": {
                        "description": "Use comparison operators with count fields",
                        "examples": [
                            "detection.grouped_details.num_attempts:>5",
                            "detection.grouped_details.num_successes:>=10",
                            "detection.grouped_details.num_events:<100",
                            "detection.grouped_details.num_matches:<=50"
                        ]
                    }
                },
                "common_patterns": {
                    "high_data_transfer": "detection.grouped_details.bytes_sent:>1000000",
                    "high_threat_score": "host.threat:>80",
                    "recent_detections": "detection.created_timestamp:>2024-01-01T00:00:00Z",
                    "many_attempts": "detection.grouped_details.num_attempts:>10",
                    "low_certainty": "detection.certainty:<30",
                    "high_certainty": "detection.certainty:>=80",
                    "many_files": "detection.grouped_details.file_count:>50",
                    "encrypted_files": "detection.grouped_details.encrypted_file_count:>5"
                },
                "best_practices": [
                    "Use :> for 'more than' queries: detection.grouped_details.bytes_sent:>1000",
                    "Use :>= for 'at least' queries: host.threat:>=80",
                    "Use :< for 'less than' queries: detection.certainty:<50",
                    "Use :<= for 'at most' queries: detection.grouped_details.file_count:<=100",
                    "Combine with boolean operators: detection.grouped_details.bytes_sent:>1000000 AND detection.category:exfiltration",
                    "Use with date ranges: detection.created_timestamp:>2024-01-01T00:00:00Z AND detection.created_timestamp:<2024-12-31T23:59:59Z"
                ]
            },
            "quoted_strings_vs_wildcards": {
                "title": "CRITICAL: Quoted Strings vs Wildcards",
                "description": "Understanding when to use quotes vs wildcards is crucial for successful queries",
                "quoted_strings": {
                    "description": "Quoted strings are for EXACT phrase matches",
                    "examples": [
                        "✅ \"Add service principal credentials\" - matches exact phrase",
                        "✅ \"Domain Admins\" - matches exact group name",
                        "✅ \"Windows Server 2019\" - matches exact OS name"
                    ]
                },
                "wildcards": {
                    "description": "Wildcards work WITHOUT quotes for pattern matching",
                    "examples": [
                        "✅ Add service principal credential* - matches phrases starting with this text",
                        "✅ Domain Admins* - matches group names starting with 'Domain Admins'",
                        "✅ Windows* - matches OS names starting with 'Windows'"
                    ],
                    "best_practices": [
                        "Use exact quotes when you know the exact phrase: \"Add service principal credentials\"",
                        "Use prefix wildcards for partial matches: Add service principal credential*",
                        "Try progressive strategy: exact quotes → prefix wildcards → suffix wildcards"
                    ]
                },
                "decision_guide": {
                    "use_quotes_when": [
                        "You know the exact phrase to match",
                        "Searching for specific detection names",
                        "Looking for exact group names",
                        "Matching exact file names or paths"
                    ],
                    "use_wildcards_when": [
                        "You need partial matching",
                        "Searching for variations of a term",
                        "Looking for items starting with specific text",
                        "Need flexible pattern matching"
                    ]
                }
            },
            "wildcard_best_practices": {
                "title": "⚠️ CRITICAL: Wildcard Usage Best Practices",
                "description": "Wildcards have specific behavior that can cause query failures if used incorrectly",
                "rules": [
                    "PREFIX WILDCARDS (ending with *) work reliably: account.ldap.member_of:Domain Admins*",
                    "SUFFIX WILDCARDS (starting with *) often FAIL: account.ldap.member_of:*Domain Admins*",
                    "EXACT MATCHES work best: account.ldap.member_of:Domain Admins",
                    "Use progressive wildcard strategy: exact → prefix → suffix → both"
                ],
                "progressive_strategy": {
                    "description": "When searching for group memberships or similar fields, try in this order:",
                    "steps": [
                        "1. Exact quotes: account.ldap.member_of:\"Domain Admins\"",
                        "2. Exact match: account.ldap.member_of:Domain Admins",
                        "3. Prefix wildcard: account.ldap.member_of:Domain Admins*", 
                        "4. Suffix wildcard: account.ldap.member_of:*Domain Admins",
                        "5. Both wildcards: account.ldap.member_of:*Domain Admins*"
                    ],
                    "note": "Stop at the first one that works. Exact quotes and prefix wildcards are most reliable."
                }
            },
            "field_types": {
                "description": "Understanding different field types",
                "types": {
                    "string": "Text fields support wildcards and phrase searches",
                    "integer": "Numeric fields support ranges and exact matches",
                    "boolean": "Use true/false values",
                    "enum": "Use exact values from the allowed list",
                    "datetime": "Use ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ",
                    "array": "Use OR operator to match any value in the array"
                }
            },
            "performance_tips": {
                "description": "Tips for optimal search performance",
                "tips": [
                    "Use specific field names instead of general text searches",
                    "Limit date ranges to avoid scanning large datasets",
                    "Use boolean operators to narrow down results",
                    "Combine multiple conditions to reduce result sets",
                    "Use pagination for large result sets",
                    "Consider using auto_paginate for comprehensive searches"
                ]
            },
            "common_patterns": {
                "description": "Common search patterns for security analysis",
                "patterns": {
                    "high_risk_entities": "threat:[80 TO 99] AND state:active",
                    "recent_activity": "last_detection_timestamp:[2024-01-01T00:00:00Z TO *]",
                    "key_asset_targeting": "is_targeting_key_asset:true AND threat:[70 TO *]",
                    "privilege_escalation": "privilege_level:[8 TO 10] AND account_type:kerberos",
                    "lateral_movement": "category:lateral AND state:active",
                    "data_exfiltration": "category:exfiltration AND is_targeting_key_asset:true",
                    "command_control": "category:command AND threat:[80 TO 99]",
                    "reconnaissance": "category:reconnaissance AND certainty:[70 TO *]"
                }
            },
            "troubleshooting": {
                "description": "Common issues and solutions",
                "issues": [
                    {
                        "issue": "No results returned",
                        "solutions": [
                            "Check field names for typos",
                            "Verify enum values are correct",
                            "Try broader date ranges",
                            "Use wildcards for partial matches"
                        ]
                    },
                    {
                        "issue": "Too many results",
                        "solutions": [
                            "Add more specific conditions",
                            "Use smaller date ranges",
                            "Add boolean operators to narrow results",
                            "Use pagination"
                        ]
                    },
                    {
                        "issue": "Unexpected results",
                        "solutions": [
                            "Check boolean operator precedence",
                            "Use parentheses for grouping",
                            "Verify field types match query syntax",
                            "Test with simpler queries first"
                        ]
                    }
                ]
            }
        }
        
        return json.dumps(content, indent=2)
    
    async def get_detection_fields_reference(self) -> str:
        """
        Comprehensive reference of all detection fields from the complete advanced search list.
        
        This resource provides detailed information about all detection fields that can be used
        in Lucene search queries, including nested fields and grouped details.
        """
        content = {
            "title": "Vectra On-Premise Detection Fields Reference",
            "description": "Complete reference of all detection fields from comprehensive advanced search list",
            "source": "Comprehensive Advanced Search Detection Fields",
            "critical_warning": {
                "title": "⚠️ CRITICAL: Singular vs Plural Field Names",
                "description": "Many fields are ARRAYS and must use PLURAL names. Using singular will cause 422 errors.",
                "array_fields_plural": {
                    "description": "These fields are ARRAYS and MUST use PLURAL names:",
                    "fields": [
                        "detection.grouped_details.dst_ips - Destination IPs",
                        "detection.grouped_details.dst_ports - Destination ports", 
                        "detection.grouped_details.target_domains - Domains",
                        "detection.grouped_details.files - Files",
                        "detection.grouped_details.extensions - File extensions",
                        "detection.grouped_details.user_agents - User agents",
                        "detection.grouped_details.encrypted_files - Encrypted files",
                        "detection.grouped_details.src_ips - Source IPs",
                        "detection.grouped_details.target_accounts - Target accounts",
                        "detection.grouped_details.dst_accounts - Destination accounts",
                        "detection.grouped_details.accounts - Accounts",
                        "detection.grouped_details.account_uids - Account UIDs"
                    ]
                },
                "string_fields_singular": {
                    "description": "These fields are STRINGS and MUST use SINGULAR names:",
                    "fields": [
                        "detection.grouped_details.src_ip - Source IP",
                        "detection.grouped_details.file_extension - File type",
                        "detection.grouped_details.url - URL pattern",
                        "detection.grouped_details.user_agent - User agent string",
                        "detection.grouped_details.protocol - Protocol",
                        "detection.grouped_details.subnet - Subnet",
                        "detection.grouped_details.account_uid - Account UID",
                        "detection.grouped_details.dst_account - Destination account",
                        "detection.grouped_details.src_account - Source account"
                    ]
                },
                "integer_fields_singular": {
                    "description": "These fields are INTEGERS and MUST use SINGULAR names:",
                    "fields": [
                        "detection.grouped_details.bytes_sent - Bytes sent",
                        "detection.grouped_details.bytes_received - Bytes received ",
                        "detection.grouped_details.encrypted_file_count - Encrypted file count",
                        "detection.grouped_details.file_count - File count",
                        "detection.grouped_details.count - Count",
                        "detection.grouped_details.duration - Duration",
                        "detection.grouped_details.volume - Volume"
                    ]
                }
            },
            "correct_examples": {
                "title": "✅ Correct Query Examples",
                "examples": [
                    {
                        "query": "detection.category:command AND detection.grouped_details.dst_ips:172.217.23.129",
                        "description": "Find C2 detections to specific IP (note: dst_ips plural)"
                    },
                    {
                        "query": "detection.grouped_details.src_ip:10.0.0.1",
                        "description": "Find detections from source IP (note: src_ip singular)"
                    },
                    {
                        "query": "detection.grouped_details.dst_ports:443",
                        "description": "Find by destination port (note: dst_ports plural)"
                    },
                    {
                        "query": "detection.grouped_details.file_extension:exe",
                        "description": "Find detections involving executable files (note: file_extension singular)"
                    },
                    {
                        "query": "detection.grouped_details.bytes_sent:>1000000",
                        "description": "Find detections with high data transfer (note: bytes_sent singular)"
                    },
                    {
                        "query": "detection.grouped_details.encrypted_file_count:>10",
                        "description": "Find detections with many encrypted files (note: encrypted_file_count singular)"
                    },
                    {
                        "query": "detection.grouped_details.account_uids:admin*",
                        "description": "Find detections involving admin accounts (note: account_uids plural)"
                    }
                ]
            },
            "basic_fields": {
                "description": "Basic detection fields",
                "fields": {
                    "id": {"type": "long", "description": "Detection ID"},
                    "assigned_date": {"type": "date", "description": "Assignment date"},
                    "assigned_to": {"type": "text", "description": "Assigned to user"},
                    "category": {"type": "text", "description": "Detection category"},
                    "certainty": {"type": "long", "description": "Certainty score (0-100)"},
                    "created_timestamp": {"type": "date", "description": "Detection creation timestamp"},
                    "custom_detection": {"type": "text", "description": "Custom detection flag"},
                    "description": {"type": "text", "description": "Detection description"},
                    "detection": {"type": "text", "description": "Detection name"},
                    "detection_category": {"type": "text", "description": "Detection category"},
                    "detection_type": {"type": "text", "description": "Detection type"},
                    "detection_url": {"type": "text", "description": "Detection URL"},
                    "filtered_by_ai": {"type": "boolean", "description": "Filtered by AI"},
                    "filtered_by_rule": {"type": "boolean", "description": "Filtered by rule"},
                    "filtered_by_user": {"type": "boolean", "description": "Filtered by user"},
                    "first_timestamp": {"type": "date", "description": "First detection timestamp"},
                    "id": {"type": "long", "description": "Detection ID"},
                    "is_custom_model": {"type": "boolean", "description": "Custom model detection"},
                    "is_marked_custom": {"type": "boolean", "description": "Marked as custom"},
                    "is_targeting_key_asset": {"type": "boolean", "description": "Targets key asset"},
                    "is_triaged": {"type": "boolean", "description": "Is triaged"},
                    "last_timestamp": {"type": "date", "description": "Last detection timestamp"},
                    "note": {"type": "text", "description": "Detection note"},
                    "note_modified_by": {"type": "text", "description": "Note modified by"},
                    "note_modified_timestamp": {"type": "date", "description": "Note modification timestamp"},
                    "normal_domains": {"type": "text", "description": "Normal domains"},
                    "sensor": {"type": "text", "description": "Sensor name"}
                }
            },
            "campaign_summaries_fields": {
                "description": "Campaign summary fields (nested under 'campaign_summaries')",
                "note": "These fields are nested under 'campaign_summaries' and can be accessed with dot notation",
                "fields": {
                    "duration": {"type": "float", "description": "Campaign duration"},
                    "id": {"type": "long", "description": "Campaign ID"},
                    "last_timestamp": {"type": "date", "description": "Last campaign timestamp"},
                    "name": {"type": "text", "description": "Campaign name"},
                    "num_detections": {"type": "long", "description": "Number of detections"},
                    "num_hosts": {"type": "long", "description": "Number of hosts"}
                }
            },
            "groups_fields": {
                "description": "Group fields (nested under 'groups')",
                "note": "These fields are nested under 'groups' and can be accessed with dot notation",
                "fields": {
                    "description": {"type": "text", "description": "Group description"},
                    "id": {"type": "long", "description": "Group ID"},
                    "last_modified": {"type": "date", "description": "Last modified"},
                    "last_modified_by": {"type": "text", "description": "Last modified by"},
                    "name": {"type": "text", "description": "Group name"},
                    "type": {"type": "text", "description": "Group type"}
                }
            },
            "grouped_details_fields": {
                "description": "Detection grouped details fields (nested)",
                "note": "These fields are nested under 'grouped_details' and can be accessed with dot notation",
                "categories": {
                    "account_fields": {
                        "description": "Account-related fields",
                        "fields": {
                            "access_key_id": {"type": "text", "description": "Access key ID"},
                            "account_created_by": {"type": "text", "description": "Account creator"},
                            "account_uid": {"type": "text", "description": "Account UID (SINGULAR)"},
                            "account_uids": {"type": "text", "description": "Account UIDs (PLURAL)"},
                            "accounts": {"type": "text", "description": "Accounts"},
                            "admin": {"type": "text", "description": "Admin flag"},
                            "assumed_role": {"type": "text", "description": "Assumed role"},
                            "aws_account_id": {"type": "text", "description": "AWS account ID"},
                            "aws_region": {"type": "text", "description": "AWS region"},
                            "dst_account": {"type": "text", "description": "Destination account (SINGULAR)"},
                            "dst_accounts": {"type": "text", "description": "Destination accounts (PLURAL)"},
                            "gcp_project_id": {"type": "text", "description": "GCP project ID"},
                            "identity": {"type": "text", "description": "Identity"},
                            "identity_type": {"type": "text", "description": "Identity type"},
                            "instance": {"type": "text", "description": "Instance"},
                            "instance_id": {"type": "text", "description": "Instance ID"},
                            "is_account_detail": {"type": "boolean", "description": "Is account detail"},
                            "job_function": {"type": "text", "description": "Job function"},
                            "kuid": {"type": "text", "description": "KUID"},
                            "ldap_cn": {"type": "text", "description": "LDAP CN"},
                            "login_type": {"type": "text", "description": "Login type"},
                            "member_list": {"type": "text", "description": "Member list"},
                            "mfa_status": {"type": "text", "description": "MFA status"},
                            "normal_account_objects": {"type": "text", "description": "Normal account objects (PLURAL)"},
                            "normal_accounts": {"type": "text", "description": "Normal accounts (PLURAL)"},
                            "normal_admin": {"type": "text", "description": "Normal admin"},
                            "normal_admins": {"type": "text", "description": "Normal admins"},
                            "normal_users": {"type": "text", "description": "Normal users (PLURAL)"},
                            "num_accounts": {"type": "long", "description": "Number of accounts (SINGULAR)"},
                            "role": {"type": "text", "description": "Role"},
                            "role_sequence": {"type": "text", "description": "Role sequence"},
                            "src_account": {"type": "text", "description": "Source account (SINGULAR)"},
                            "target_accounts": {"type": "text", "description": "Target accounts (PLURAL)"},
                            "team_name": {"type": "text", "description": "Team name"},
                            "unusual_accounts": {"type": "text", "description": "Unusual accounts"},
                            "user_type": {"type": "text", "description": "User type"}
                        }
                    },
                    "network_fields": {
                        "description": "Network-related fields - CRITICAL: Note singular vs plural",
                        "fields": {
                            "src_ip": {"type": "text", "description": "Source IP (SINGULAR - string field)"},
                            "src_ips": {"type": "text", "description": "Source IPs (PLURAL - array field)"},
                            "dst_ips": {"type": "text", "description": "Destination IPs (PLURAL - array field)"},
                            "dst_ports": {"type": "long", "description": "Destination ports (PLURAL - array field)"},
                            "src_port": {"type": "long", "description": "Source port (SINGULAR)"},
                            "protocol": {"type": "text", "description": "Protocol (SINGULAR - string field)"},
                            "dst_protocol": {"type": "text", "description": "Destination protocol (SINGULAR - string field)"},
                            "origin_protocol": {"type": "text", "description": "Origin protocol (SINGULAR)"},
                            "subnet": {"type": "text", "description": "Subnet (SINGULAR - string field)"},
                            "dst_subnets": {"type": "text", "description": "Destination subnets (PLURAL - array field)"},
                            "origin_ip": {"type": "text", "description": "Origin IP (SINGULAR)"},
                            "origin_port": {"type": "long", "description": "Origin port (SINGULAR)"},
                            "proxy_ip": {"type": "text", "description": "Proxy IP (SINGULAR)"},
                            "listener_ip": {"type": "text", "description": "Listener IP (SINGULAR)"},
                            "listener_port": {"type": "long", "description": "Listener port (SINGULAR)"},
                            "ports": {"type": "long", "description": "Ports (PLURAL)"},
                            "app_protocol": {"type": "text", "description": "Application protocol (SINGULAR)"},
                            "client_application": {"type": "text", "description": "Client application (SINGULAR)"},
                            "client_name": {"type": "text", "description": "Client name (SINGULAR)"},
                            "client_token": {"type": "text", "description": "Client token (SINGULAR)"},
                            "communication_type": {"type": "text", "description": "Communication type (SINGULAR)"},
                            "dst_cdn": {"type": "text", "description": "Destination CDN (SINGULAR)"},
                            "cdn_ips": {"type": "text", "description": "CDN IPs (PLURAL)"},
                            "normal_cdn_ips": {"type": "text", "description": "Normal CDN IPs (PLURAL)"},
                            "normal_connection_count": {"type": "long", "description": "Normal connection count (SINGULAR)"},
                            "normal_dst_ips": {"type": "text", "description": "Normal destination IPs (PLURAL)"},
                            "normal_dst_ports": {"type": "long", "description": "Normal destination ports (PLURAL)"},
                            "normal_origin_ips": {"type": "text", "description": "Normal origin IPs (PLURAL)"},
                            "normal_origin_ports": {"type": "long", "description": "Normal origin ports (PLURAL)"},
                            "normal_port": {"type": "long", "description": "Normal port (SINGULAR)"},
                            "normal_ports": {"type": "long", "description": "Normal ports (PLURAL)"},
                            "normal_subnets": {"type": "text", "description": "Normal subnets (PLURAL)"},
                            "origin_domain": {"type": "text", "description": "Origin domain (SINGULAR)"},
                            "resp_domain": {"type": "text", "description": "Response domain (SINGULAR)"},
                            "suspicious_flow_connectors": {"type": "text", "description": "Suspicious flow connectors (PLURAL)"},
                            "baseline_flow_connectors": {"type": "text", "description": "Baseline flow connectors (PLURAL)"},
                            "other_flow_connectors": {"type": "text", "description": "Other flow connectors (PLURAL)"},
                            "flow_connector_count": {"type": "long", "description": "Flow connector count (SINGULAR)"},
                            "flow_connectors": {"type": "text", "description": "Flow connectors (PLURAL)"},
                            "flow_owner": {"type": "text", "description": "Flow owner (SINGULAR)"},
                            "flow_uuid": {"type": "text", "description": "Flow UUID (SINGULAR)"},
                            "network_type": {"type": "text", "description": "Network type (SINGULAR)"},
                            "is_external": {"type": "boolean", "description": "Is external (SINGULAR)"},
                            "is_smallsweep": {"type": "boolean", "description": "Is small sweep (SINGULAR)"},
                            "distinct_traffic_ids": {"type": "text", "description": "Distinct traffic IDs (PLURAL)"},
                            "dns_response": {"type": "text", "description": "DNS response (SINGULAR)"},
                            "dos_type": {"type": "text", "description": "DoS type (SINGULAR)"},
                            "cipher_response": {"type": "text", "description": "Cipher response (SINGULAR)"},
                            "ciphers_requested": {"type": "text", "description": "Ciphers requested (PLURAL)"}
                        }
                    },
                    "file_fields": {
                        "description": "File-related fields - CRITICAL: Note singular vs plural",
                        "fields": {
                            "file": {"type": "text", "description": "File (SINGULAR - string field)"},
                            "files": {"type": "text", "description": "Files (PLURAL - array field)"},
                            "file_count": {"type": "long", "description": "File count (SINGULAR - integer field)"},
                            "file_name": {"type": "text", "description": "File name (SINGULAR - string field)"},
                            "file_extension": {"type": "text", "description": "File extension (SINGULAR - string field)"},
                            "original_extension": {"type": "text", "description": "Original extension (SINGULAR)"},
                            "original_extensions": {"type": "text", "description": "Original extensions (PLURAL)"},
                            "encrypted_extension": {"type": "text", "description": "Encrypted extension (SINGULAR)"},
                            "encrypted_file_count": {"type": "long", "description": "Encrypted file count (SINGULAR - integer field)"},
                            "encrypted_files": {"type": "text", "description": "Encrypted files (PLURAL - array field)"},
                            "encrypted_share": {"type": "text", "description": "Encrypted share (SINGULAR)"},
                            "extensions_bytes": {"type": "text", "description": "Extensions bytes (PLURAL)"},
                            "extension_extensions": {"type": "text", "description": "Extension extensions (PLURAL)"},
                            "extensions": {"type": "text", "description": "File extensions (PLURAL)"},
                            "num_encrypted_extensions": {"type": "long", "description": "Number of encrypted extensions (SINGULAR)"},
                            "share": {"type": "text", "description": "Share (SINGULAR)"},
                            "shares": {"type": "text", "description": "Shares (PLURAL)"},
                            "normal_share": {"type": "text", "description": "Normal share (SINGULAR)"},
                            "normal_shares": {"type": "text", "description": "Normal shares (PLURAL)"},
                            "common_shares": {"type": "text", "description": "Common shares (PLURAL)"},
                            "num_shares": {"type": "long", "description": "Number of shares (SINGULAR)"},
                            "artifact": {"type": "text", "description": "Artifact (SINGULAR)"},
                            "object": {"type": "text", "description": "Object (SINGULAR)"},
                            "objects": {"type": "text", "description": "Objects (PLURAL)"},
                            "object_type": {"type": "text", "description": "Object type (SINGULAR)"},
                            "resource": {"type": "text", "description": "Resource (SINGULAR)"},
                            "target_objects": {"type": "text", "description": "Target objects (PLURAL)"},
                            "full_path": {"type": "text", "description": "Full path (SINGULAR)"},
                            "folder_name": {"type": "text", "description": "Folder name (SINGULAR)"},
                            "files_table": {"type": "text", "description": "Files table (PLURAL)"},
                            "malware_file_count": {"type": "long", "description": "Malware file count (SINGULAR)"},
                            "malware_files": {"type": "text", "description": "Malware files (PLURAL)"},
                            "num_files": {"type": "long", "description": "Number of files (SINGULAR)"},
                            "hashes_count": {"type": "long", "description": "Hashes count (SINGULAR)"}
                        }
                    },
                    "web_fields": {
                        "description": "Web-related fields - CRITICAL: Note singular vs plural",
                        "fields": {
                            "url": {"type": "text", "description": "URL (SINGULAR - string field)"},
                            "uri": {"type": "text", "description": "URI (SINGULAR)"},
                            "user_agent": {"type": "text", "description": "User agent (SINGULAR - string field)"},
                            "user_agents": {"type": "text", "description": "User agents (PLURAL - array field)"},
                            "http_method": {"type": "text", "description": "HTTP method (SINGULAR - string field)"},
                            "http_methods": {"type": "text", "description": "HTTP methods (PLURAL)"},
                            "http_segment": {"type": "text", "description": "HTTP segment (SINGULAR)"},
                            "http_status": {"type": "text", "description": "HTTP status (SINGULAR)"},
                            "response_code": {"type": "text", "description": "Response code (SINGULAR - string field)"},
                            "referrer": {"type": "text", "description": "Referrer (SINGULAR - string field)"},
                            "browser": {"type": "text", "description": "Browser (SINGULAR - string field)"},
                            "client": {"type": "text", "description": "Client (SINGULAR - string field)"},
                            "client_application": {"type": "text", "description": "Client application (SINGULAR - string field)"},
                            "client_name": {"type": "text", "description": "Client name (SINGULAR - string field)"},
                            "headless_browser": {"type": "text", "description": "Headless browser (SINGULAR)"},
                            "first_seen_browser": {"type": "text", "description": "First seen browser (SINGULAR)"},
                            "last_seen_browser": {"type": "text", "description": "Last seen browser (SINGULAR)"},
                            "normal_user_agent": {"type": "text", "description": "Normal user agent (SINGULAR)"},
                            "unusual_clients": {"type": "text", "description": "Unusual clients (PLURAL)"},
                            "request_parameters": {"type": "text", "description": "Request parameters (PLURAL)"},
                            "resolved_parameters": {"type": "text", "description": "Resolved parameters (PLURAL)"},
                            "response_elements": {"type": "text", "description": "Response elements (PLURAL)"},
                            "via": {"type": "text", "description": "Via (SINGULAR)"},
                            "x_forwarded_for": {"type": "text", "description": "X-Forwarded-For (SINGULAR)"},
                            "expire_time_cache_control": {"type": "text", "description": "Expire time cache control (SINGULAR)"},
                            "reply_cache_control": {"type": "text", "description": "Reply cache control (SINGULAR)"},
                            "js_entropy_score": {"type": "float", "description": "JS entropy score (SINGULAR)"},
                            "video_codec": {"type": "text", "description": "Video codec (SINGULAR)"},
                            "sql_fragment": {"type": "text", "description": "SQL fragment (SINGULAR)"},
                            "query": {"type": "text", "description": "Query (SINGULAR)"},
                            "realm": {"type": "text", "description": "Realm (SINGULAR)"},
                            "cred_obtained": {"type": "text", "description": "Credential obtained (SINGULAR)"},
                            "session_context": {"type": "text", "description": "Session context (SINGULAR)"},
                            "sessions": {"type": "text", "description": "Sessions (PLURAL)"},
                            "services": {"type": "text", "description": "Services (PLURAL)"},
                            "service_accessed": {"type": "text", "description": "Service accessed (SINGULAR)"},
                            "service_accesses": {"type": "text", "description": "Service accesses (PLURAL)"},
                            "directories": {"type": "text", "description": "Directories (PLURAL)"},
                            "domain_controllers": {"type": "text", "description": "Domain controllers (PLURAL)"},
                            "dst_hosts": {"type": "text", "description": "Destination hosts objects. Valid keys are: dst_hosts.dst_host.id, dst_hosts.dst_host.ip, dst_hosts.dst_host.name, dst_hosts.type, dst_hosts.dst_port, dst_hosts.dst_ip, dst_hosts.name"},
                            "src_host": {"type": "text", "description": "Source hosts objects. Valid keys are: src_host.id, src_host.ip, src_host.name, src_host.key_asset, src_host.privilege_level, src_host.privilege_category"},
                            "target_host": {"type": "text", "description": "Target host (SINGULAR)"},
                            "targets": {"type": "text", "description": "Targets (PLURAL)"},
                            "events": {"type": "text", "description": "Events (PLURAL)"},
                            "extent": {"type": "text", "description": "Extent (SINGULAR)"},
                            "http_method_counts": {"type": "text", "description": "HTTP method counts (PLURAL)"},
                            "operation_commands": {"type": "text", "description": "Operation commands (PLURAL)"},
                            "operation_details": {"type": "text", "description": "Operation details (PLURAL)"},
                            "operation_privilege": {"type": "text", "description": "Operation privilege (SINGULAR)"},
                            "resolved_parameters": {"type": "text", "description": "Resolved parameters (PLURAL)"},
                            "service_accessed": {"type": "text", "description": "Service accessed (SINGULAR)"},
                            "service_accesses": {"type": "text", "description": "Service accesses (PLURAL)"},
                            "session_context": {"type": "text", "description": "Session context (SINGULAR)"},
                            "sessions": {"type": "text", "description": "Sessions (PLURAL)"},
                            "src_account": {"type": "text", "description": "Source account (SINGULAR)"},
                            "src_host": {"type": "text", "description": "Source host (SINGULAR)"},
                            "src_profiles": {"type": "text", "description": "Source profiles (PLURAL)"},
                            "dst_profiles": {"type": "text", "description": "Destination profiles (PLURAL)"},
                            "target_accounts": {"type": "text", "description": "Target accounts (PLURAL)"},
                            "target_domains": {"type": "text", "description": "Target domains (PLURAL)"},
                            "target_entity": {"type": "text", "description": "Target entity (SINGULAR)"},
                            "target_host": {"type": "text", "description": "Target host (SINGULAR)"},
                            "target_objects": {"type": "text", "description": "Target objects (PLURAL)"},
                            "targets": {"type": "text", "description": "Targets (PLURAL)"},
                            "unusual_accounts": {"type": "text", "description": "Unusual accounts (PLURAL)"},
                            "unusual_clients": {"type": "text", "description": "Unusual clients (PLURAL)"},
                            "unusual_domain_controllers": {"type": "text", "description": "Unusual domain controllers (PLURAL)"},
                            "unusual_instances": {"type": "long", "description": "Unusual instances (PLURAL)"},
                            "unusual_services": {"type": "text", "description": "Unusual services (PLURAL)"},
                            "user_personal_sharepoint": {"type": "text", "description": "User personal SharePoint (SINGULAR)"},
                            "via": {"type": "text", "description": "Via (SINGULAR)"},
                            "volume": {"type": "long", "description": "Volume (SINGULAR)"},
                            "x_forwarded_for": {"type": "text", "description": "X-Forwarded-For (SINGULAR)"}
                        }
                    },
                    "email_fields": {
                        "description": "Email-related fields",
                        "fields": {
                            "email": {"type": "text", "description": "Email address"},
                            "destination_email": {"type": "text", "description": "Destination email (SINGULAR)"},
                            "destination_emails": {"type": "text", "description": "Destination emails (PLURAL)"},
                            "recipients": {"type": "text", "description": "Recipients (PLURAL)"},
                            "recipients_count": {"type": "long", "description": "Recipients count (SINGULAR)"},
                            "num_recipients": {"type": "long", "description": "Number of recipients (SINGULAR)"},
                            "subject": {"type": "text", "description": "Email subject (SINGULAR)"},
                            "message": {"type": "text", "description": "Message (SINGULAR)"},
                            "user_personal_sharepoint": {"type": "text", "description": "Personal SharePoint (SINGULAR)"},
                            "forwarded_mailboxes": {"type": "text", "description": "Forwarded mailboxes (PLURAL)"},
                            "exchange_locations": {"type": "text", "description": "Exchange locations (PLURAL)"},
                            "num_mailboxes_forwarded": {"type": "long", "description": "Number of mailboxes forwarded (SINGULAR)"},
                            "mailboxes": {"type": "text", "description": "Mailboxes (PLURAL)"}
                        }
                    },
                    "behavioral_fields": {
                        "description": "Behavioral analysis fields",
                        "fields": {
                            "behavior": {"type": "text", "description": "Behavior (SINGULAR)"},
                            "anomalous_profiles": {"type": "text", "description": "Anomalous profiles (PLURAL)"},
                            "attempts": {"type": "long", "description": "Attempt count (SINGULAR)"},
                            "num_attempts": {"type": "long", "description": "Number of attempts (SINGULAR)"},
                            "num_access_attempts": {"type": "long", "description": "Number of access attempts (SINGULAR)"},
                            "num_failed_accesses": {"type": "long", "description": "Number of failed accesses (SINGULAR)"},
                            "duration": {"type": "long", "description": "Duration (SINGULAR)"},
                            "first_seen": {"type": "date", "description": "First seen (SINGULAR)"},
                            "first_seen_activity": {"type": "date", "description": "First seen activity (SINGULAR)"},
                            "first_seen_device_name": {"type": "text", "description": "First seen device name (SINGULAR)"},
                            "first_seen_impossible_travel": {"type": "text", "description": "First seen impossible travel (SINGULAR)"},
                            "first_seen_os": {"type": "text", "description": "First seen OS (SINGULAR)"},
                            "first_seen_city": {"type": "text", "description": "First seen city (SINGULAR)"},
                            "first_seen_country": {"type": "text", "description": "First seen country (SINGULAR)"},
                            "first_timestamp": {"type": "date", "description": "First timestamp (SINGULAR)"},
                            "last_seen": {"type": "date", "description": "Last seen (SINGULAR)"},
                            "last_seen_device_name": {"type": "text", "description": "Last seen device name (SINGULAR)"},
                            "last_seen_os": {"type": "text", "description": "Last seen OS (SINGULAR)"},
                            "last_seen_city": {"type": "text", "description": "Last seen city (SINGULAR)"},
                            "last_seen_country": {"type": "text", "description": "Last seen country (SINGULAR)"},
                            "last_timestamp": {"type": "date", "description": "Last timestamp (SINGULAR)"},
                            "first_geo_shift": {"type": "text", "description": "First geo shift (SINGULAR)"},
                            "last_geo_shift": {"type": "text", "description": "Last geo shift (SINGULAR)"},
                            "previous_countries": {"type": "text", "description": "Previous countries (PLURAL)"},
                            "previous_device_names": {"type": "text", "description": "Previous device names (PLURAL)"},
                            "previous_os_browsers": {"type": "text", "description": "Previous OS browsers (PLURAL)"},
                            "normal_device_names": {"type": "text", "description": "Normal device names (PLURAL)"},
                            "normal_os_browsers": {"type": "text", "description": "Normal OS browsers (PLURAL)"},
                            "normal_locations": {"type": "text", "description": "Normal locations (PLURAL)"},
                            "normal_countries": {"type": "text", "description": "Normal countries (PLURAL)"},
                            "normal_origin_geo": {"type": "text", "description": "Normal origin geo (SINGULAR)"},
                            "normal_dst_geo": {"type": "text", "description": "Normal destination geo (SINGULAR)"},
                            "dst_geo": {"type": "text", "description": "Destination geo (SINGULAR)"},
                            "dst_geo_lat": {"type": "float", "description": "Destination geo latitude (SINGULAR)"},
                            "dst_geo_lon": {"type": "float", "description": "Destination geo longitude (SINGULAR)"},
                            "origin_geo": {"type": "text", "description": "Origin geo (SINGULAR)"},
                            "origin_geo_lat": {"type": "float", "description": "Origin geo latitude (SINGULAR)"},
                            "origin_geo_lon": {"type": "float", "description": "Origin geo longitude (SINGULAR)"},
                            "location_lat": {"type": "float", "description": "Location latitude (SINGULAR)"},
                            "location_lon": {"type": "float", "description": "Location longitude (SINGULAR)"},
                            "city": {"type": "text", "description": "City (SINGULAR)"},
                            "country": {"type": "text", "description": "Country (SINGULAR)"},
                            "device_name": {"type": "text", "description": "Device name (SINGULAR)"},
                            "dhcp_name": {"type": "text", "description": "DHCP name (SINGULAR)"},
                            "nic_name": {"type": "text", "description": "NIC name (SINGULAR)"},
                            "product_id": {"type": "text", "description": "Product ID (SINGULAR)"},
                            "vendor": {"type": "text", "description": "Vendor (SINGULAR)"},
                            "mode": {"type": "text", "description": "Mode (SINGULAR)"},
                            "state": {"type": "text", "description": "State (SINGULAR)"},
                            "operation": {"type": "text", "description": "Operation (SINGULAR)"},
                            "operations": {"type": "text", "description": "Operations (PLURAL)"},
                            "operation_count": {"type": "text", "description": "Operation count (SINGULAR)"},
                            "operation_commands": {"type": "text", "description": "Operation commands (PLURAL)"},
                            "operation_details": {"type": "text", "description": "Operation details (PLURAL)"},
                            "operation_privilege": {"type": "text", "description": "Operation privilege (SINGULAR)"},
                            "num_privileged_operations": {"type": "long", "description": "Number of privileged operations (SINGULAR)"},
                            "probable_attack": {"type": "text", "description": "Probable attack (SINGULAR)"},
                            "primary_match": {"type": "text", "description": "Primary match (SINGULAR)"},
                            "matches": {"type": "text", "description": "Matches (PLURAL)"},
                            "other_matches": {"type": "text", "description": "Other matches (PLURAL)"},
                            "period_identified": {"type": "text", "description": "Period identified (SINGULAR)"},
                            "num_periods": {"type": "long", "description": "Number of periods (SINGULAR)"},
                            "reasons": {"type": "text", "description": "Reasons (PLURAL)"},
                            "reason": {"type": "text", "description": "Reason (SINGULAR)"},
                            "failed_reason": {"type": "text", "description": "Failed reason (SINGULAR)"},
                            "result": {"type": "text", "description": "Result (SINGULAR)"},
                            "results": {"type": "text", "description": "Results (PLURAL)"},
                            "error_code": {"type": "text", "description": "Error code (SINGULAR)"},
                            "error_message": {"type": "text", "description": "Error message (SINGULAR)"},
                            "error_number": {"type": "long", "description": "Error number (SINGULAR)"},
                            "event": {"type": "text", "description": "Event (SINGULAR)"},
                            "event_description": {"type": "text", "description": "Event description (SINGULAR)"},
                            "event_id": {"type": "text", "description": "Event ID (SINGULAR)"},
                            "event_name": {"type": "text", "description": "Event name (SINGULAR)"},
                            "event_type": {"type": "text", "description": "Event type (SINGULAR)"},
                            "log_type": {"type": "text", "description": "Log type (SINGULAR)"},
                            "authentication_method": {"type": "text", "description": "Authentication method (SINGULAR)"},
                            "attacker_detail": {"type": "text", "description": "Attacker detail (SINGULAR)"},
                            "affected_trail": {"type": "text", "description": "Affected trail (SINGULAR)"},
                            "ad_category": {"type": "text", "description": "AD category (SINGULAR)"},
                            "application": {"type": "text", "description": "Application (SINGULAR)"},
                            "app_name": {"type": "text", "description": "Application name (SINGULAR)"},
                            "app_protocol": {"type": "text", "description": "Application protocol (SINGULAR)"},
                            "command": {"type": "text", "description": "Command (SINGULAR)"},
                            "command_arguments": {"type": "text", "description": "Command arguments (PLURAL)"},
                            "function": {"type": "text", "description": "Function (SINGULAR)"},
                            "function_call": {"type": "text", "description": "Function call (SINGULAR)"},
                            "function_uuid": {"type": "text", "description": "Function UUID (SINGULAR)"},
                            "src_profiles": {"type": "text", "description": "Source profiles (PLURAL)"},
                            "dst_profiles": {"type": "text", "description": "Destination profiles (PLURAL)"},
                            "count": {"type": "long", "description": "Count (SINGULAR)"},
                            "num_accounts": {"type": "long", "description": "Number of accounts (SINGULAR)"},
                            "num_events": {"type": "long", "description": "Number of events (SINGULAR)"},
                            "num_normal_events": {"type": "long", "description": "Number of normal events (SINGULAR)"},
                            "num_processes": {"type": "long", "description": "Number of processes (SINGULAR)"},
                            "num_sessions": {"type": "long", "description": "Number of sessions (SINGULAR)"},
                            "num_scans": {"type": "long", "description": "Number of scans (SINGULAR)"},
                            "num_ldap_profiles": {"type": "long", "description": "Number of LDAP profiles (SINGULAR)"},
                            "num_access_keys": {"type": "long", "description": "Number of access keys (SINGULAR)"},
                            "num_accessed_by_other_hosts": {"type": "long", "description": "Number accessed by other hosts (SINGULAR)"},
                            "num_new_for_dst_host": {"type": "long", "description": "Number new for destination host (SINGULAR)"},
                            "num_new_for_src_host": {"type": "long", "description": "Number new for source host (SINGULAR)"},
                            "flow_count": {"type": "long", "description": "Flow count (SINGULAR)"},
                            "volume": {"type": "long", "description": "Volume (SINGULAR)"},
                            "scope": {"type": "text", "description": "Scope (SINGULAR)"},
                            "search_id": {"type": "text", "description": "Search ID (SINGULAR)"},
                            "detection_slug": {"type": "text", "description": "Detection slug (SINGULAR)"},
                            "detection_source": {"type": "text", "description": "Detection source (SINGULAR)"},
                            "rule_name": {"type": "text", "description": "Rule name (SINGULAR)"},
                            "uuid": {"type": "text", "description": "UUID (SINGULAR)"},
                            "oid": {"type": "text", "description": "OID (SINGULAR)"},
                            "old_val": {"type": "text", "description": "Old value (SINGULAR)"},
                            "new_val": {"type": "text", "description": "New value (SINGULAR)"},
                            "change": {"type": "text", "description": "Change (SINGULAR)"},
                            "description": {"type": "text", "description": "Description (SINGULAR)"},
                            "name": {"type": "text", "description": "Name (SINGULAR)"},
                            "target": {"type": "text", "description": "Target (SINGULAR)"},
                            "target_entity": {"type": "text", "description": "Target entity (SINGULAR)"},
                            "target_domains": {"type": "text", "description": "Target domains (PLURAL)"},
                            "external_target": {"type": "text", "description": "External target (SINGULAR)"},
                            "external_host": {"type": "text", "description": "External host (SINGULAR)"},
                            "src_external_host": {"type": "text", "description": "Source external host (SINGULAR)"},
                            "host": {"type": "text", "description": "Host (SINGULAR)"},
                            "ip": {"type": "text", "description": "IP (SINGULAR)"},
                            "ip_address": {"type": "text", "description": "IP address (SINGULAR)"},
                            "ip_addresses": {"type": "text", "description": "IP addresses (PLURAL)"},
                            "key_asset": {"type": "boolean", "description": "Key asset (SINGULAR)"},
                            "max_severity": {"type": "text", "description": "Max severity (SINGULAR)"},
                            "threat_feeds": {"type": "text", "description": "Threat feeds (PLURAL)"},
                            "threat_feed": {"type": "text", "description": "Threat feed (SINGULAR)"},
                            "distinct_traffic_ids": {"type": "text", "description": "Distinct traffic IDs (PLURAL)"},
                            "received_pattern": {"type": "text", "description": "Received pattern (SINGULAR)"},
                            "sent_pattern": {"type": "text", "description": "Sent pattern (SINGULAR)"},
                            "received_normal_pattern": {"type": "text", "description": "Received normal pattern (SINGULAR)"},
                            "sent_normal_pattern": {"type": "text", "description": "Sent normal pattern (SINGULAR)"},
                            "normal_events_sum": {"type": "long", "description": "Normal events sum (SINGULAR)"},
                            "normal_bytes_received": {"type": "long", "description": "Normal bytes received (SINGULAR)"},
                            "normal_bytes_sent": {"type": "long", "description": "Normal bytes sent (SINGULAR)"},
                            "normal_processes": {"type": "long", "description": "Normal processes (PLURAL)"},
                            "normal_uri": {"type": "text", "description": "Normal URI (SINGULAR)"},
                            "normal_uris": {"type": "text", "description": "Normal URIs (PLURAL)"},
                            "normal_dst_hosts": {"type": "text", "description": "Normal destination hosts (PLURAL)"},
                            "unusual_instances": {"type": "long", "description": "Unusual instances (PLURAL)"},
                            "unusual_services": {"type": "text", "description": "Unusual services (PLURAL)"},
                            "unusual_domain_controllers": {"type": "text", "description": "Unusual domain controllers (PLURAL)"},
                            "last_source_hosts": {"type": "text", "description": "Last source hosts (PLURAL)"},
                            "last_couch_time": {"type": "date", "description": "Last couch time (SINGULAR)"},
                            "date_couch": {"type": "date", "description": "Date couch (SINGULAR)"},
                            "date_first_bucket": {"type": "date", "description": "Date first bucket (SINGULAR)"},
                            "date_publish": {"type": "date", "description": "Date publish (SINGULAR)"},
                            "created_timestamp": {"type": "date", "description": "Created timestamp (SINGULAR)"},
                            "effective_session_interval_seconds": {"type": "text", "description": "Effective session interval seconds (SINGULAR)"},
                            "cipher_response": {"type": "text", "description": "Cipher response (SINGULAR)"},
                            "ciphers_requested": {"type": "text", "description": "Ciphers requested (PLURAL)"},
                            "dns_response": {"type": "text", "description": "DNS response (SINGULAR)"},
                            "dos_type": {"type": "text", "description": "DoS type (SINGULAR)"},
                            "expire_time_cache_control": {"type": "text", "description": "Expire time cache control (SINGULAR)"},
                            "reply_cache_control": {"type": "text", "description": "Reply cache control (SINGULAR)"},
                            "js_entropy_score": {"type": "float", "description": "JS entropy score (SINGULAR)"},
                            "video_codec": {"type": "text", "description": "Video codec (SINGULAR)"},
                            "sql_fragment": {"type": "text", "description": "SQL fragment (SINGULAR)"},
                            "query": {"type": "text", "description": "Query (SINGULAR)"},
                            "realm": {"type": "text", "description": "Realm (SINGULAR)"},
                            "cred_obtained": {"type": "text", "description": "Credential obtained (SINGULAR)"},
                            "session_context": {"type": "text", "description": "Session context (SINGULAR)"},
                            "sessions": {"type": "text", "description": "Sessions (PLURAL)"},
                            "services": {"type": "text", "description": "Services (PLURAL)"},
                            "service_accessed": {"type": "text", "description": "Service accessed (SINGULAR)"},
                            "service_accesses": {"type": "text", "description": "Service accesses (PLURAL)"},
                            "directories": {"type": "text", "description": "Directories (PLURAL)"},
                            "domain_controllers": {"type": "text", "description": "Domain controllers (PLURAL)"},
                            "dst_hosts": {"type": "text", "description": "Destination hosts (PLURAL)"},
                            "src_hosts": {"type": "text", "description": "Source hosts (PLURAL)"},
                            "target_host": {"type": "text", "description": "Target host (SINGULAR)"},
                            "targets": {"type": "text", "description": "Targets (PLURAL)"},
                            "events": {"type": "text", "description": "Events (PLURAL)"},
                            "extent": {"type": "text", "description": "Extent (SINGULAR)"},
                            "http_method_counts": {"type": "text", "description": "HTTP method counts (PLURAL)"},
                            "operation_commands": {"type": "text", "description": "Operation commands (PLURAL)"},
                            "operation_details": {"type": "text", "description": "Operation details (PLURAL)"},
                            "operation_privilege": {"type": "text", "description": "Operation privilege (SINGULAR)"},
                            "resolved_parameters": {"type": "text", "description": "Resolved parameters (PLURAL)"},
                            "service_accessed": {"type": "text", "description": "Service accessed (SINGULAR)"},
                            "service_accesses": {"type": "text", "description": "Service accesses (PLURAL)"},
                            "session_context": {"type": "text", "description": "Session context (SINGULAR)"},
                            "sessions": {"type": "text", "description": "Sessions (PLURAL)"},
                            "src_account": {"type": "text", "description": "Source account (SINGULAR)"},
                            "src_host": {"type": "text", "description": "Source host (SINGULAR)"},
                            "src_profiles": {"type": "text", "description": "Source profiles (PLURAL)"},
                            "dst_profiles": {"type": "text", "description": "Destination profiles (PLURAL)"},
                            "target_accounts": {"type": "text", "description": "Target accounts (PLURAL)"},
                            "target_domains": {"type": "text", "description": "Target domains (PLURAL)"},
                            "target_entity": {"type": "text", "description": "Target entity (SINGULAR)"},
                            "target_host": {"type": "text", "description": "Target host (SINGULAR)"},
                            "target_objects": {"type": "text", "description": "Target objects (PLURAL)"},
                            "targets": {"type": "text", "description": "Targets (PLURAL)"},
                            "unusual_accounts": {"type": "text", "description": "Unusual accounts (PLURAL)"},
                            "unusual_clients": {"type": "text", "description": "Unusual clients (PLURAL)"},
                            "unusual_domain_controllers": {"type": "text", "description": "Unusual domain controllers (PLURAL)"},
                            "unusual_instances": {"type": "long", "description": "Unusual instances (PLURAL)"},
                            "unusual_services": {"type": "text", "description": "Unusual services (PLURAL)"},
                            "user_personal_sharepoint": {"type": "text", "description": "User personal SharePoint (SINGULAR)"},
                            "via": {"type": "text", "description": "Via (SINGULAR)"},
                            "volume": {"type": "long", "description": "Volume (SINGULAR)"},
                            "x_forwarded_for": {"type": "text", "description": "X-Forwarded-For (SINGULAR)"}
                        }
                    },
                    "data_transfer_fields": {
                        "description": "Data transfer fields - CRITICAL: All are SINGULAR integer fields",
                        "fields": {
                            "bytes_sent": {"type": "long", "description": "Bytes sent (SINGULAR - integer field)"},
                            "bytes_received": {"type": "long", "description": "Bytes received (SINGULAR - integer field)"},
                            "total_bytes_sent": {"type": "long", "description": "Total bytes sent (SINGULAR - integer field)"},
                            "total_bytes_rcvd": {"type": "long", "description": "Total bytes received (SINGULAR - integer field)"},
                            "normal_bytes_sent": {"type": "long", "description": "Normal bytes sent (SINGULAR - integer field)"},
                            "normal_bytes_received": {"type": "long", "description": "Normal bytes received (SINGULAR - integer field)"}
                        }
                    },
                    "ja3_ja3s_fields": {
                        "description": "JA3/JA3S hash fields for TLS fingerprinting",
                        "fields": {
                            "ja3_hash": {"type": "text", "description": "JA3 hash (SINGULAR)"},
                            "ja3_hashes": {"type": "text", "description": "JA3 hashes (PLURAL)"},
                            "ja3s_hash": {"type": "text", "description": "JA3S hash (SINGULAR)"},
                            "ja3s_hashes": {"type": "text", "description": "JA3S hashes (PLURAL)"}
                        }
                    },
                    "operation_fields": {
                        "description": "Operation and privilege-related fields",
                        "fields": {
                            "operation": {"type": "text", "description": "Operation (SINGULAR)"},
                            "operations": {"type": "text", "description": "Operations (PLURAL)"},
                            "operation_count": {"type": "text", "description": "Operation count (SINGULAR)"},
                            "operation_commands": {"type": "text", "description": "Operation commands (PLURAL)"},
                            "operation_details": {"type": "text", "description": "Operation details (PLURAL)"},
                            "operation_privilege": {"type": "text", "description": "Operation privilege (SINGULAR)"},
                            "operation_privilege_privilege": {"type": "long", "description": "Operation privilege level (SINGULAR)"},
                            "operation_privilege_privilegeCategory": {"type": "text", "description": "Operation privilege category (SINGULAR)"},
                            "operation_details_display_name": {"type": "text", "description": "Operation details display name (SINGULAR)"},
                            "operation_details_new_value": {"type": "text", "description": "Operation details new value (SINGULAR)"},
                            "operation_details_old_value": {"type": "text", "description": "Operation details old value (SINGULAR)"},
                            "operation_commands_command": {"type": "text", "description": "Operation commands command (SINGULAR)"},
                            "operation_commands_command_arguments": {"type": "text", "description": "Operation commands command arguments (PLURAL)"},
                            "operation_commands_operation": {"type": "text", "description": "Operation commands operation (SINGULAR)"},
                            "operation_commands_timestamp": {"type": "date", "description": "Operation commands timestamp (SINGULAR)"},
                            "normal_operations": {"type": "text", "description": "Normal operations (PLURAL)"},
                            "num_privileged_operations": {"type": "long", "description": "Number of privileged operations (SINGULAR)"},
                            "num_services_high_privilege": {"type": "long", "description": "Number of services high privilege (SINGULAR)"},
                            "num_services_requested": {"type": "long", "description": "Number of services requested (SINGULAR)"}
                        }
                    },
                    "service_fields": {
                        "description": "Service access and behavior fields",
                        "fields": {
                            "service_accessed": {"type": "text", "description": "Service accessed (SINGULAR)"},
                            "service_accesses": {"type": "text", "description": "Service accesses (PLURAL)"},
                            "service_accessed_name": {"type": "text", "description": "Service accessed name (SINGULAR)"},
                            "service_accessed_privilege_category": {"type": "text", "description": "Service accessed privilege category (SINGULAR)"},
                            "service_accessed_privilege_level": {"type": "long", "description": "Service accessed privilege level (SINGULAR)"},
                            "service_accesses_first_seen": {"type": "date", "description": "Service accesses first seen (SINGULAR)"},
                            "service_accesses_last_seen": {"type": "date", "description": "Service accesses last seen (SINGULAR)"},
                            "service_accesses_name": {"type": "text", "description": "Service accesses name (SINGULAR)"},
                            "service_accesses_privilege_category": {"type": "text", "description": "Service accesses privilege category (SINGULAR)"},
                            "service_accesses_privilege_level": {"type": "long", "description": "Service accesses privilege level (SINGULAR)"},
                            "service_accesses_normal_service_behavior": {"type": "text", "description": "Service accesses normal service behavior (PLURAL)"},
                            "normal_services": {"type": "text", "description": "Normal services (PLURAL)"},
                            "unusual_services": {"type": "text", "description": "Unusual services (PLURAL)"}
                        }
                    },
                    "session_fields": {
                        "description": "Session and connection fields",
                        "fields": {
                            "sessions": {"type": "text", "description": "Sessions (PLURAL)"},
                            "sessions_app_protocol": {"type": "text", "description": "Sessions app protocol (SINGULAR)"},
                            "sessions_bytes_received": {"type": "long", "description": "Sessions bytes received (SINGULAR)"},
                            "sessions_bytes_sent": {"type": "long", "description": "Sessions bytes sent (SINGULAR)"},
                            "sessions_dst_ip": {"type": "text", "description": "Sessions destination IP (SINGULAR)"},
                            "sessions_dst_port": {"type": "long", "description": "Sessions destination port (SINGULAR)"},
                            "sessions_first_timestamp": {"type": "date", "description": "Sessions first timestamp (SINGULAR)"},
                            "sessions_last_timestamp": {"type": "date", "description": "Sessions last timestamp (SINGULAR)"},
                            "sessions_protocol": {"type": "text", "description": "Sessions protocol (SINGULAR)"},
                            "sessions_tunnel_type": {"type": "text", "description": "Sessions tunnel type (SINGULAR)"},
                            "sessions_target_host": {"type": "text", "description": "Sessions target host (SINGULAR)"},
                            "sessions_created_timestamp": {"type": "date", "description": "Sessions created timestamp (SINGULAR)"},
                            "sessions_duration": {"type": "long", "description": "Sessions duration (SINGULAR)"},
                            "num_sessions": {"type": "long", "description": "Number of sessions (SINGULAR)"},
                            "num_ad_sessions": {"type": "long", "description": "Number of AD sessions (SINGULAR)"},
                            "effective_session_interval_seconds": {"type": "text", "description": "Effective session interval seconds (SINGULAR)"},
                            "session_context": {"type": "text", "description": "Session context (SINGULAR)"},
                            "session_context_context": {"type": "text", "description": "Session context context (SINGULAR)"},
                            "session_context_source": {"type": "text", "description": "Session context source (SINGULAR)"}
                        }
                    },
                    "target_fields": {
                        "description": "Target and destination fields",
                        "fields": {
                            "target": {"type": "text", "description": "Target (SINGULAR)"},
                            "targets": {"type": "text", "description": "Targets (PLURAL)"},
                            "target_entity": {"type": "text", "description": "Target entity (SINGULAR)"},
                            "target_host": {"type": "text", "description": "Target host (SINGULAR)"},
                            "target_host_dst_dns": {"type": "text", "description": "Target host destination DNS (SINGULAR)"},
                            "target_host_id": {"type": "long", "description": "Target host ID (SINGULAR)"},
                            "target_host_ip": {"type": "text", "description": "Target host IP (SINGULAR)"},
                            "target_host_name": {"type": "text", "description": "Target host name (SINGULAR)"},
                            "target_domains": {"type": "text", "description": "Target domains (PLURAL)"},
                            "target_objects": {"type": "text", "description": "Target objects (PLURAL)"},
                            "target_objects_target": {"type": "text", "description": "Target objects target (SINGULAR)"},
                            "targets_dst_hosts": {"type": "text", "description": "Targets destination hosts (PLURAL)"},
                            "targets_events": {"type": "text", "description": "Targets events (PLURAL)"},
                            "targets_events_bytes_received": {"type": "long", "description": "Targets events bytes received (SINGULAR)"},
                            "targets_events_http_segment": {"type": "text", "description": "Targets events HTTP segment (SINGULAR)"},
                            "targets_events_last_seen": {"type": "date", "description": "Targets events last seen (SINGULAR)"},
                            "targets_events_response_code": {"type": "text", "description": "Targets events response code (SINGULAR)"},
                            "targets_events_sql_fragment": {"type": "text", "description": "Targets events SQL fragment (SINGULAR)"},
                            "targets_events_user_agent": {"type": "text", "description": "Targets events user agent (SINGULAR)"}
                        }
                    }
                }
            },
            "usage_examples": {
                "description": "Examples of how to use these fields in search queries - CRITICAL: Note correct singular/plural usage",
                "examples": [
                    {
                        "query": "detection.category:command",
                        "description": "Find command and control detections"
                    },
                    {
                        "query": "detection.grouped_details.src_ip:192.168.1.100",
                        "description": "Find detections from specific source IP (note: src_ip is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.dst_ips:172.217.23.129",
                        "description": "Find detections targeting specific destination IP (note: dst_ips is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.dst_ports:443",
                        "description": "Find detections targeting port 443 (note: dst_ports is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.file_extension:exe",
                        "description": "Find detections involving executable files (note: file_extension is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.files:malware.exe",
                        "description": "Find detections involving specific files (note: files is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.bytes_sent:[1000000 TO *]",
                        "description": "Find detections with high data transfer (note: bytes_sent is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.encrypted_file_count:[10 TO *]",
                        "description": "Find detections with many encrypted files (note: encrypted_file_count is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.account_uids:admin*",
                        "description": "Find detections involving admin accounts (note: account_uids is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.user_agent:bot",
                        "description": "Find detections with exact user agent 'bot' (exact match - most reliable)"
                    },
                    {
                        "query": "detection.grouped_details.user_agent:bot*",
                        "description": "Find detections with user agents starting with 'bot' (prefix wildcard)"
                    },
                    {
                        "query": "detection.grouped_details.user_agents:*bot*",
                        "description": "Find detections with bot user agents (note: user_agents is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.url:malicious",
                        "description": "Find detections with exact URL 'malicious' (exact match - most reliable)"
                    },
                    {
                        "query": "detection.grouped_details.url:malicious*",
                        "description": "Find detections with URLs starting with 'malicious' (prefix wildcard)"
                    },
                    {
                        "query": "detection.grouped_details.target_domains:example.com",
                        "description": "Find detections targeting specific domain (note: target_domains is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.protocol:https",
                        "description": "Find detections using HTTPS protocol (note: protocol is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.duration:[3600 TO *]",
                        "description": "Find detections lasting more than 1 hour (note: duration is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.count:[100 TO *]",
                        "description": "Find detections with high count (note: count is SINGULAR)"
                    },
                    {
                        "query": "detection.campaign_summaries.name:ransomware*",
                        "description": "Find detections in ransomware campaigns"
                    },
                    {
                        "query": "detection.campaign_summaries.num_detections:[10 TO *]",
                        "description": "Find detections in campaigns with many detections"
                    },
                    {
                        "query": "detection.groups.name:investigation*",
                        "description": "Find detections in investigation groups"
                    },
                    {
                        "query": "detection.groups.type:custom",
                        "description": "Find detections in custom groups"
                    },
                    {
                        "query": "detection.assigned_to:analyst*",
                        "description": "Find detections assigned to analysts"
                    },
                    {
                        "query": "detection.assigned_date:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections assigned since January 1, 2024"
                    },
                    {
                        "query": "detection.filtered_by_ai:true",
                        "description": "Find detections filtered by AI"
                    },
                    {
                        "query": "detection.filtered_by_rule:true",
                        "description": "Find detections filtered by rule"
                    },
                    {
                        "query": "detection.filtered_by_user:true",
                        "description": "Find detections filtered by user"
                    },
                    {
                        "query": "detection.is_custom_model:true",
                        "description": "Find custom model detections"
                    },
                    {
                        "query": "detection.is_marked_custom:true",
                        "description": "Find detections marked as custom"
                    },
                    {
                        "query": "detection.is_triaged:true",
                        "description": "Find triaged detections"
                    },
                    {
                        "query": "detection.is_targeting_key_asset:true",
                        "description": "Find detections targeting key assets"
                    },
                    {
                        "query": "detection.certainty:[80 TO 99]",
                        "description": "Find high-certainty detections"
                    },
                    {
                        "query": "detection.created_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections created since January 1, 2024"
                    },
                    {
                        "query": "detection.first_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with first activity since January 1, 2024"
                    },
                    {
                        "query": "detection.last_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with recent activity since January 1, 2024"
                    },
                    {
                        "query": "detection.sensor:DMZ*",
                        "description": "Find detections from DMZ sensors"
                    },
                    {
                        "query": "detection.normal_domains:internal*",
                        "description": "Find detections with normal internal domains"
                    },
                    {
                        "query": "detection.custom_detection:true",
                        "description": "Find custom detections"
                    },
                    {
                        "query": "detection.note:*investigation*",
                        "description": "Find detections with investigation notes"
                    },
                    {
                        "query": "detection.note_modified_by:analyst*",
                        "description": "Find detections with notes modified by analysts"
                    },
                    {
                        "query": "detection.note_modified_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with notes modified since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.ja3_hash:abc123*",
                        "description": "Find detections with specific JA3 hash (note: ja3_hash is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.ja3_hashes:*bot*",
                        "description": "Find detections with bot-related JA3 hashes (note: ja3_hashes is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.ja3s_hash:def456*",
                        "description": "Find detections with specific JA3S hash (note: ja3s_hash is SINGULAR)"
                    },
                    {
                        "query": "detection.grouped_details.metadata_hassh:*malicious*",
                        "description": "Find detections with malicious HASSH fingerprints"
                    },
                    {
                        "query": "detection.grouped_details.metadata_issuer:*suspicious*",
                        "description": "Find detections with suspicious certificate issuers"
                    },
                    {
                        "query": "detection.grouped_details.events_bytes_sent:[1000000 TO *]",
                        "description": "Find detections with high event data transfer"
                    },
                    {
                        "query": "detection.grouped_details.events_dst_ips:192.168.1.*",
                        "description": "Find detections targeting internal network (note: events_dst_ips is PLURAL)"
                    },
                    {
                        "query": "detection.grouped_details.keyboard_id:*suspicious*",
                        "description": "Find detections with suspicious keyboard IDs"
                    },
                    {
                        "query": "detection.grouped_details.mac_address:00:11:22:33:44:55",
                        "description": "Find detections from specific MAC address"
                    },
                    {
                        "query": "detection.grouped_details.operation_privilege_privilege:[8 TO 10]",
                        "description": "Find detections with high privilege operations"
                    },
                    {
                        "query": "detection.grouped_details.service_accesses_privilege_level:[8 TO 10]",
                        "description": "Find detections with high privilege service accesses"
                    },
                    {
                        "query": "detection.grouped_details.sessions_tunnel_type:*vpn*",
                        "description": "Find detections with VPN tunnel sessions"
                    },
                    {
                        "query": "detection.grouped_details.target_host_key_asset:true",
                        "description": "Find detections targeting key asset hosts"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_user_agent:*bot*",
                        "description": "Find detections with bot user agents in target events"
                    },
                    {
                        "query": "detection.grouped_details.ip_login_attempts_num_attempts:[10 TO *]",
                        "description": "Find detections with many login attempts"
                    },
                    {
                        "query": "detection.grouped_details.flex_json_threat_score:[80 TO 99]",
                        "description": "Find detections with high threat scores in flex JSON"
                    },
                    {
                        "query": "detection.grouped_details.executed_functions:*malicious*",
                        "description": "Find detections with malicious executed functions"
                    },
                    {
                        "query": "detection.grouped_details.named_pipe:*admin*",
                        "description": "Find detections with admin-related named pipes"
                    },
                    {
                        "query": "detection.grouped_details.indicators:*ransomware*",
                        "description": "Find detections with ransomware indicators"
                    },
                    {
                        "query": "detection.grouped_details.match_context:*privilege*",
                        "description": "Find detections with privilege-related match context"
                    },
                    {
                        "query": "detection.grouped_details.multi_fields:*suspicious*",
                        "description": "Find detections with suspicious multi fields"
                    },
                    {
                        "query": "detection.grouped_details.scope:*internal*",
                        "description": "Find detections with internal scope"
                    },
                    {
                        "query": "detection.grouped_details.search_id:*investigation*",
                        "description": "Find detections with investigation search IDs"
                    },
                    {
                        "query": "detection.grouped_details.detection_slug:*malware*",
                        "description": "Find detections with malware-related slugs"
                    },
                    {
                        "query": "detection.grouped_details.rule_name:*custom*",
                        "description": "Find detections from custom rules"
                    },
                    {
                        "query": "detection.grouped_details.num_observations:[100 TO *]",
                        "description": "Find detections with many observations"
                    },
                    {
                        "query": "detection.grouped_details.num_matches:[50 TO *]",
                        "description": "Find detections with many matches"
                    },
                    {
                        "query": "detection.grouped_details.num_successes:[10 TO *]",
                        "description": "Find detections with many successes"
                    },
                    {
                        "query": "detection.grouped_details.normal_product_ids:*microsoft*",
                        "description": "Find detections with Microsoft product IDs in normal behavior"
                    },
                    {
                        "query": "detection.grouped_details.unusual_instances:[5 TO *]",
                        "description": "Find detections with many unusual instances"
                    },
                    {
                        "query": "detection.grouped_details.date_couch:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with couch data since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.date_first_bucket:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with first bucket data since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.date_publish:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections published since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.last_couch_time:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with recent couch time since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.effective_session_interval_seconds:*3600*",
                        "description": "Find detections with 1-hour session intervals"
                    },
                    {
                        "query": "detection.grouped_details.session_context_context:*admin*",
                        "description": "Find detections with admin session context"
                    },
                    {
                        "query": "detection.grouped_details.session_context_source:*external*",
                        "description": "Find detections with external session context source"
                    },
                    {
                        "query": "detection.grouped_details.num_ad_sessions:[5 TO *]",
                        "description": "Find detections with many AD sessions"
                    },
                    {
                        "query": "detection.grouped_details.sessions_created_timestamp:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with sessions created since January 1, 2024"
                    },
                    {
                        "query": "detection.grouped_details.sessions_duration:[3600 TO *]",
                        "description": "Find detections with sessions lasting more than 1 hour"
                    },
                    {
                        "query": "detection.grouped_details.sessions_tunnel_type:*ssh*",
                        "description": "Find detections with SSH tunnel sessions"
                    },
                    {
                        "query": "detection.grouped_details.targets_dst_hosts:*server*",
                        "description": "Find detections targeting servers"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_sql_fragment:*select*",
                        "description": "Find detections with SQL SELECT statements in target events"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_http_segment:*admin*",
                        "description": "Find detections with admin HTTP segments in target events"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_response_code:200",
                        "description": "Find detections with successful HTTP responses in target events"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_last_seen:[2024-01-01T00:00:00Z TO *]",
                        "description": "Find detections with recent target event activity"
                    },
                    {
                        "query": "detection.grouped_details.targets_events_bytes_received:[1000000 TO *]",
                        "description": "Find detections with high data reception in target events"
                    }
                ]
            },
            "field_access_patterns": {
                "description": "How to access nested fields in Lucene queries - CRITICAL: Use correct singular/plural field names",
                "patterns": [
                    "Use dot notation for nested fields: detection.grouped_details.src_ip",
                    "CRITICAL: Use PLURAL names for array fields: detection.grouped_details.dst_ips",
                    "CRITICAL: Use SINGULAR names for string fields: detection.grouped_details.src_ip",
                    "Access array elements: detection.grouped_details.files",
                    "Access string fields: detection.grouped_details.file_extension ",
                    "Use ranges for numeric fields: detection.grouped_details.bytes_sent:[1000 TO 5000]",
                    "Use operators for numeric fields: detection.grouped_details.bytes_sent:>5000",
                    "Use PREFIX wildcards for text fields: detection.grouped_details.url:suspicious*",
                    "For URL searches, try: exact → prefix → suffix → both wildcards",
                    "Example progression: detection.grouped_details.url:suspicious → suspicious* → *suspicious → *suspicious*",
                    "Combine multiple conditions: detection.category:lateral AND detection.grouped_details.src_ip:192.168.1.*",
                    "Common mistake: detection.grouped_details.dst_ips:172.217.23.129",
                    "Common mistake: detection.grouped_details.src_ip:10.0.0.1"
                ]
            }
        }
        
        return json.dumps(content, indent=2)
    
    async def get_account_fields_reference(self) -> str:
        """
        Comprehensive reference of all account fields from Advanced_Search_Accounts.md.
        
        This resource provides detailed information about all account fields that can be used
        in Lucene search queries, including nested fields and detection summaries.
        """
        content = {
            "title": "Vectra On-Premise Account Fields Reference",
            "description": "Complete reference of all account fields from Advanced_Search_Accounts.md",
            "source": "Advanced_Search_Accounts.md",
            "basic_fields": {
                "description": "Basic account fields",
                "fields": {
                    "id": {"type": "long", "description": "Account ID"},
                    "name": {"type": "text", "description": "Account name"},
                    "account_type": {"type": "text", "description": "Account type"},
                    "threat": {"type": "long", "description": "Threat score"},
                    "certainty": {"type": "long", "description": "Certainty score"},
                    "severity": {"type": "text", "description": "Severity level"},
                    "state": {"type": "text", "description": "Account state"},
                    "privilege_level": {"type": "long", "description": "Privilege level"},
                    "privilege_category": {"type": "text", "description": "Privilege category"},
                    "last_detection_timestamp": {"type": "date", "description": "Last detection timestamp"},
                    "detection_set": {"type": "text", "description": "Detection set"},
                    "probable_home_host": {"type": "text", "description": "Probable home host"},
                    "note": {"type": "text", "description": "Account note"},
                    "note_modified_by": {"type": "text", "description": "Note modified by"},
                    "note_modified_timestamp": {"type": "date", "description": "Note modification timestamp"},
                    "tags": {"type": "text", "description": "Account tags"}
                }
            },
            "ldap_fields": {
                "description": "LDAP account fields (nested under 'ldap')",
                "note": "These fields are nested under 'ldap' and can be accessed with dot notation",
                "fields": {
                    "account_disabled": {"type": "boolean", "description": "Account disabled status"},
                    "account_lockedout": {"type": "boolean", "description": "Account locked out status"},
                    "common_name": {"type": "text", "description": "Common name"},
                    "data_gathered_at": {"type": "text", "description": "Data gathered timestamp"},
                    "department": {"type": "text", "description": "Department"},
                    "description": {"type": "text", "description": "Description"},
                    "display_name": {"type": "text", "description": "Display name"},
                    "distinguished_name": {"type": "text", "description": "Distinguished name"},
                    "email": {"type": "text", "description": "Email address"},
                    "employee_type": {"type": "text", "description": "Employee type"},
                    "location": {"type": "text", "description": "Location"},
                    "managed_by": {"type": "text", "description": "Managed by"},
                    "manager": {"type": "text", "description": "Manager"},
                    "member_of": {"type": "text", "description": "Member of groups"},
                    "netbios_name": {"type": "text", "description": "NetBIOS name"},
                    "ntsecurity_descriptor": {"type": "text", "description": "NT security descriptor"},
                    "object_class": {"type": "text", "description": "Object class"},
                    "object_sid": {"type": "text", "description": "Object SID"},
                    "organization": {"type": "text", "description": "Organization"},
                    "password_expired": {"type": "boolean", "description": "Password expired status"},
                    "pwd_last_set": {"type": "date", "description": "Password last set date"},
                    "sAMAccountName": {"type": "text", "description": "SAM account name"},
                    "telephone_number": {"type": "text", "description": "Telephone number"},
                    "timestamp": {"type": "date", "description": "LDAP timestamp"},
                    "title": {"type": "text", "description": "Job title"},
                    "user_principal_name": {"type": "text", "description": "User principal name"}
                }
            },
            "detection_summaries_fields": {
                "description": "Account detection summaries fields (nested)",
                "note": "These fields are nested under 'detection_summaries' and can be accessed with dot notation",
                "basic_summary_fields": {
                    "description": "Basic detection summary fields",
                    "fields": {
                        "detection_id": {"type": "long", "description": "Detection ID"},
                        "detection_type": {"type": "text", "description": "Detection type"},
                        "detection_category": {"type": "text", "description": "Detection category"},
                        "certainty": {"type": "long", "description": "Detection certainty"},
                        "threat": {"type": "long", "description": "Detection threat score"},
                        "state": {"type": "text", "description": "Detection state"},
                        "is_targeting_key_asset": {"type": "boolean", "description": "Targets key asset"},
                        "is_triaged": {"type": "boolean", "description": "Is triaged"},
                        "tags": {"type": "text", "description": "Detection tags"}
                    }
                },
                "summary_details_fields": {
                    "description": "Detailed summary fields (nested under 'summary') - Complete list from Advanced_Search_Accounts.md",
                    "fields": {
                        "account_uids": {"type": "text", "description": "Account UIDs"},
                        "app_name": {"type": "text", "description": "Application name"},
                        "app_names": {"type": "text", "description": "Application names"},
                        "client_applications": {"type": "text", "description": "Client applications"},
                        "commands": {"type": "text", "description": "Commands executed"},
                        "countries": {"type": "text", "description": "Countries"},
                        "description": {"type": "text", "description": "Summary description"},
                        "destination_emails": {"type": "text", "description": "Destination emails"},
                        "display_names": {"type": "text", "description": "Display names"},
                        "emails": {"type": "text", "description": "Email addresses"},
                        "encrypted_extensions": {"type": "text", "description": "Encrypted file extensions"},
                        "encrypted_file_count": {"type": "long", "description": "Encrypted file count"},
                        "files_downloaded": {"type": "long", "description": "Files downloaded count"},
                        "login_attempts": {"type": "long", "description": "Login attempts count"},
                        "malware_files": {"type": "long", "description": "Malware files count"},
                        "mfa_status": {"type": "text", "description": "MFA status"},
                        "num_attempts": {"type": "long", "description": "Number of attempts"},
                        "num_mailboxes_forwarded": {"type": "long", "description": "Number of mailboxes forwarded"},
                        "operations": {"type": "text", "description": "Operations performed"},
                        "oss": {"type": "text", "description": "Operating systems"},
                        "reasons": {"type": "text", "description": "Reasons"},
                        "recipients": {"type": "text", "description": "Recipients"},
                        "recipients_count": {"type": "long", "description": "Recipients count"},
                        "shares": {"type": "text", "description": "Shared resources"},
                        "src_ips": {"type": "text", "description": "Source IPs"},
                        "subject": {"type": "text", "description": "Email subject"},
                        "target_list": {"type": "text", "description": "Target list"},
                        "team_names": {"type": "text", "description": "Team names"},
                        "user_agents": {"type": "text", "description": "User agents"},
                        "workloads": {"type": "text", "description": "Workloads"}
                    }
                },
                "services_accessed_fields": {
                    "description": "Services accessed fields (nested under 'services_accessed')",
                    "fields": {
                        "name": {"type": "text", "description": "Service name"},
                        "privilege_category": {"type": "text", "description": "Privilege category"},
                        "privilege_level": {"type": "long", "description": "Privilege level"}
                    }
                },
                "src_accounts_fields": {
                    "description": "Source accounts fields (nested under 'src_accounts')",
                    "fields": {
                        "id": {"type": "long", "description": "Source account ID"},
                        "name": {"type": "text", "description": "Source account name"},
                        "privilege_category": {"type": "text", "description": "Privilege category"},
                        "privilege_level": {"type": "long", "description": "Privilege level"}
                    }
                },
                "src_hosts_fields": {
                    "description": "Source hosts fields (nested under 'src_hosts')",
                    "fields": {
                        "id": {"type": "long", "description": "Source host ID"},
                        "name": {"type": "text", "description": "Source host name"},
                        "privilege_category": {"type": "text", "description": "Privilege category"},
                        "privilege_level": {"type": "long", "description": "Privilege level"}
                    }
                }
            },
            "usage_examples": {
                "description": "Examples of how to use these fields in search queries",
                "examples": [
                    {
                        "query": "account.name:admin*",
                        "description": "Find accounts with names starting with 'admin'"
                    },
                    {
                        "query": "account.privilege_level:[8 TO 10]",
                        "description": "Find accounts with high privilege levels"
                    },
                    {
                        "query": "account.ldap.department:IT",
                        "description": "Find accounts in IT department"
                    },
                    {
                        "query": "account.ldap.password_expired:true",
                        "description": "Find accounts with expired passwords"
                    },
                    {
                        "query": "account.detection_summaries.threat:[80 TO 99]",
                        "description": "Find accounts with high-threat detections"
                    },
                    {
                        "query": "account.detection_summaries.summary.files_downloaded:[100 TO *]",
                        "description": "Find accounts with many file downloads"
                    },
                    {
                        "query": "account.detection_summaries.summary.mfa_status:disabled",
                        "description": "Find accounts with disabled MFA"
                    },
                    {
                        "query": "account.ldap.member_of:Domain Admins",
                        "description": "Find accounts in Domain Admins group (exact match - most reliable)"
                    },
                    {
                        "query": "account.ldap.member_of:Domain Admins*",
                        "description": "Find accounts in groups starting with 'Domain Admins' (prefix wildcard)"
                    },
                    {
                        "query": "account.ldap.member_of:*Domain Admins",
                        "description": "Find accounts in groups ending with 'Domain Admins' (suffix wildcard - less reliable)"
                    }
                ]
            },
            "field_access_patterns": {
                "description": "How to access nested fields in Lucene queries",
                "patterns": [
                    "Use dot notation for nested fields: account.ldap.department",
                    "Access detection summary fields: account.detection_summaries.threat",
                    "Access summary details: account.detection_summaries.summary.files_downloaded",
                    "Use ranges for numeric fields: account.privilege_level:[8 TO 10]",
                    "Use PREFIX wildcards for text fields: account.name:admin*",
                    "For group memberships, try: exact → prefix → suffix → both wildcards",
                    "Example progression: account.ldap.member_of:Domain Admins → Domain Admins* → *Domain Admins → *Domain Admins*",
                    "Combine multiple conditions: account.ldap.password_expired:true AND account.privilege_level:[8 TO 10]"
                ]
            }
        }
        
        return json.dumps(content, indent=2)
    
    async def get_host_fields_reference(self) -> str:
        """
        Comprehensive reference of all host fields from Advanced_Search_Hosts.md.
        
        This resource provides detailed information about all host fields that can be used
        in Lucene search queries, including nested fields and detection summaries.
        """
        content = {
            "title": "Vectra On-Premise Host Fields Reference",
            "description": "Complete reference of all host fields from Advanced_Search_Hosts.md",
            "source": "Advanced_Search_Hosts.md",
            "basic_fields": {
                "description": "Basic host fields - called with host.id, host.name, etc.",
                "fields": {
                    "id": {"type": "long", "description": "Host ID"},
                    "name": {"type": "text", "description": "Host name"},
                    "ip": {"type": "text", "description": "Host IP address"},
                    "threat": {"type": "long", "description": "Threat score"},
                    "certainty": {"type": "long", "description": "Certainty score"},
                    "severity": {"type": "text", "description": "Severity level"},
                    "state": {"type": "text", "description": "Host state"},
                    "privilege_level": {"type": "integer", "description": "Privilege level"},
                    "privilege_category": {"type": "text", "description": "Privilege category"},
                    "last_detection_timestamp": {"type": "date", "description": "Last detection timestamp"},
                    "detection_set": {"type": "text", "description": "Detection set"},
                    "detection_profile": {"type": "text", "description": "Host detection profile."},
                    "probable_owner": {"type": "text", "description": "Probable owner"},
                    "sensor": {"type": "text", "description": "Sensor name"},
                    "sensor_name": {"type": "text", "description": "Sensor name"},
                    "is_key_asset": {"type": "boolean", "description": "Is key asset"},
                    "targets_key_asset": {"type": "boolean", "description": "Targets key asset"},
                    "active_traffic": {"type": "boolean", "description": "Active traffic"},
                    "note": {"type": "text", "description": "Host note"},
                    "note_modified_by": {"type": "text", "description": "Note modified by"},
                    "note_modified_timestamp": {"type": "date", "description": "Note modification timestamp"},
                    "tags": {"type": "text", "description": "Host tags"},
                    "assigned_to": {"type": "text", "description": "Assigned to user"},
                    "assigned_date": {"type": "date", "description": "Assignment date"}
                }
            },
            "ldap_fields": {
                "description": "Host LDAP fields (nested under 'ldap')",
                "note": "These fields are nested under 'ldap' and can be accessed with dot notation",
                "fields": {
                    "account_disabled": {"type": "boolean", "description": "Account disabled status"},
                    "account_lockedout": {"type": "boolean", "description": "Account locked out status"},
                    "common_name": {"type": "text", "description": "Common name"},
                    "data_gathered_at": {"type": "text", "description": "Data gathered timestamp"},
                    "department": {"type": "text", "description": "Department"},
                    "description": {"type": "text", "description": "Description"},
                    "display_name": {"type": "text", "description": "Display name"},
                    "distinguished_name": {"type": "text", "description": "Distinguished name"},
                    "dns_host_name": {"type": "text", "description": "DNS host name"},
                    "dns_hostname": {"type": "text", "description": "DNS hostname"},
                    "email": {"type": "text", "description": "Email address"},
                    "employee_type": {"type": "text", "description": "Employee type"},
                    "location": {"type": "text", "description": "Location"},
                    "mac_address": {"type": "text", "description": "MAC address"},
                    "machine_role": {"type": "text", "description": "Machine role"},
                    "managed_by": {"type": "text", "description": "Managed by"},
                    "manager": {"type": "text", "description": "Manager"},
                    "member_of": {"type": "text", "description": "Member of groups"},
                    "netbios_name": {"type": "text", "description": "NetBIOS name"},
                    "network_address": {"type": "text", "description": "Network address"},
                    "ntsecurity_descriptor": {"type": "text", "description": "NT security descriptor"},
                    "object_class": {"type": "text", "description": "Object class"},
                    "object_sid": {"type": "text", "description": "Object SID"},
                    "operating_system": {"type": "text", "description": "Operating system ruuning on the host"},
                    "organization": {"type": "text", "description": "Organization"},
                    "password_expired": {"type": "boolean", "description": "Password expired status"},
                    "physical_location_object": {"type": "text", "description": "Physical location object"},
                    "pwd_last_set": {"type": "date", "description": "Password last set date"},
                    "sAMAccountName": {"type": "text", "description": "SAM account name"},
                    "service_principal_name": {"type": "text", "description": "Service principal name"},
                    "timestamp": {"type": "date", "description": "LDAP timestamp"},
                    "title": {"type": "text", "description": "Job title"},
                    "user_principal_name": {"type": "text", "description": "User principal name"}
                }
            },
            "assignment_fields": {
                "description": "Host assignment fields (nested under 'assignment')",
                "note": "These fields are nested under 'assignment' and can be accessed with dot notation",
                "fields": {
                    "id": {"type": "long", "description": "Assignment ID"},
                    "host_id": {"type": "long", "description": "Host ID"},
                    "date_assigned": {"type": "date", "description": "Assignment date"},
                    "assigned_by": {"type": "text", "description": "Assigned by user"},
                    "assigned_to": {"type": "text", "description": "Assigned to user"}
                }
            },
            "detection_summaries_fields": {
                "description": "Host detection summaries fields (nested)",
                "note": "These fields are nested under 'detection_summaries' and can be accessed with dot notation",
                "basic_summary_fields": {
                    "description": "Basic detection summary fields",
                    "fields": {
                        "detection_id": {"type": "long", "description": "Detection ID"},
                        "detection_type": {"type": "text", "description": "Detection type"},
                        "detection_category": {"type": "text", "description": "Detection category"},
                        "detection_url": {"type": "text", "description": "Detection URL"},
                        "certainty": {"type": "long", "description": "Detection certainty"},
                        "threat": {"type": "long", "description": "Detection threat score"},
                        "state": {"type": "text", "description": "Detection state"},
                        "is_targeting_key_asset": {"type": "boolean", "description": "Targets key asset"},
                        "is_triaged": {"type": "boolean", "description": "Is triaged"},
                        "assigned_to": {"type": "text", "description": "Assigned to user"},
                        "assigned_date": {"type": "date", "description": "Assignment date"},
                        "tags": {"type": "text", "description": "Detection tags"}
                    }
                },
                "summary_details_fields": {
                    "description": "Detailed summary fields (nested under 'summary')",
                    "fields": {
                        "abnormal_data_rate": {"type": "long", "description": "Abnormal data rate"},
                        "accounts": {"type": "text", "description": "Accounts"},
                        "active_time": {"type": "text", "description": "Active time"},
                        "app_protocols": {"type": "text", "description": "Application protocols"},
                        "artifact": {"type": "text", "description": "Artifact"},
                        "authentication_attempts": {"type": "long", "description": "Authentication attempts"},
                        "bad_user_agent": {"type": "long", "description": "Bad user agent count"},
                        "beaconing": {"type": "long", "description": "Beaconing count"},
                        "bytes_received": {"type": "long", "description": "Bytes received"},
                        "bytes_sent": {"type": "long", "description": "Bytes sent"},
                        "cdn": {"type": "text", "description": "CDN information"},
                        "client_names": {"type": "text", "description": "Client names"},
                        "client_tokens": {"type": "text", "description": "Client tokens"},
                        "common_shares": {"type": "text", "description": "Common shares"},
                        "custom_model_query": {"type": "text", "description": "Custom model query"},
                        "dark_ips_contacted": {"type": "text", "description": "Dark IPs contacted"},
                        "description": {"type": "text", "description": "Summary description"},
                        "distinct_traffic_ids": {"type": "long", "description": "Distinct traffic IDs"},
                        "dos_types": {"type": "text", "description": "DoS types"},
                        "dst_ips": {"type": "text", "description": "Destination IPs"},
                        "dst_ports": {"type": "long", "description": "Destination ports"},
                        "duration": {"type": "long", "description": "Duration"},
                        "executed_functions": {"type": "text", "description": "Executed functions"},
                        "files": {"type": "text", "description": "Files"},
                        "first_matched": {"type": "date", "description": "First matched"},
                        "first_timestamp": {"type": "date", "description": "First timestamp"},
                        "function_uuids": {"type": "text", "description": "Function UUIDs"},
                        "ja3_hashes": {"type": "text", "description": "JA3 hashes"},
                        "last_matched": {"type": "date", "description": "Last matched"},
                        "last_timestamp": {"type": "date", "description": "Last timestamp"},
                        "mac_address": {"type": "text", "description": "MAC address"},
                        "mac_randomization": {"type": "text", "description": "MAC randomization"},
                        "matches": {"type": "long", "description": "Matches count"},
                        "normal_bytes_received": {"type": "float", "description": "Normal bytes received"},
                        "num_accounts": {"type": "long", "description": "Number of accounts"},
                        "num_attempts": {"type": "long", "description": "Number of attempts"},
                        "num_dst_ips": {"type": "long", "description": "Number of destination IPs"},
                        "num_events": {"type": "long", "description": "Number of events"},
                        "num_failures": {"type": "long", "description": "Number of failures"},
                        "num_files": {"type": "long", "description": "Number of files"},
                        "num_requests": {"type": "long", "description": "Number of requests"},
                        "num_response_objects": {"type": "long", "description": "Number of response objects"},
                        "num_sessions": {"type": "long", "description": "Number of sessions"},
                        "num_shares": {"type": "long", "description": "Number of shares"},
                        "num_successes": {"type": "long", "description": "Number of successes"},
                        "origin_ips": {"type": "text", "description": "Origin IPs"},
                        "ports": {"type": "long", "description": "Ports"},
                        "probable_owner": {"type": "text", "description": "Probable owner"},
                        "protocol_ports": {"type": "text", "description": "Protocol ports"},
                        "protocols": {"type": "text", "description": "Protocols"},
                        "reason": {"type": "text", "description": "Reason"},
                        "roles": {"type": "text", "description": "Roles"},
                        "services": {"type": "text", "description": "Services"},
                        "src_ips": {"type": "text", "description": "Source IPs"},
                        "subnet": {"type": "text", "description": "Subnet"},
                        "target_domains": {"type": "text", "description": "Target domains"},
                        "target_hosts": {"type": "text", "description": "Target hosts"},
                        "target_ips": {"type": "text", "description": "Target IPs"},
                        "target_ports": {"type": "long", "description": "Target ports"},
                        "targets": {"type": "text", "description": "Targets"},
                        "total_bytes_received": {"type": "long", "description": "Total bytes received"},
                        "total_bytes_sent": {"type": "long", "description": "Total bytes sent"},
                        "total_duration": {"type": "long", "description": "Total duration"},
                        "total_events": {"type": "long", "description": "Total events"},
                        "total_sessions": {"type": "long", "description": "Total sessions"},
                        "user_agents": {"type": "text", "description": "User agents"},
                        "workloads": {"type": "text", "description": "Workloads"}
                    }
                },
                "domain_controllers_fields": {
                    "description": "Domain controllers fields (nested under 'domain_controllers')",
                    "fields": {
                        "id": {"type": "long", "description": "Domain controller ID"},
                        "ip": {"type": "text", "description": "Domain controller IP"},
                        "name": {"type": "text", "description": "Domain controller name"}
                    }
                },
                "dst_hosts_fields": {
                    "description": "Destination hosts fields (nested under 'dst_hosts')",
                    "fields": {
                        "id": {"type": "long", "description": "Destination host ID"},
                        "ip": {"type": "text", "description": "Destination host IP"},
                        "name": {"type": "text", "description": "Destination host name"},
                        "type": {"type": "text", "description": "Destination host type"}
                    }
                }
            },
            "campaign_fields": {
                "description": "Campaign-related fields",
                "fields": {
                    "campaign_summaries": {
                        "description": "Campaign summary fields",
                        "fields": {
                            "id": {"type": "long", "description": "Campaign ID"},
                            "name": {"type": "text", "description": "Campaign name"},
                            "duration": {"type": "float", "description": "Campaign duration"},
                            "num_detections": {"type": "long", "description": "Number of detections"},
                            "num_hosts": {"type": "long", "description": "Number of hosts"},
                            "last_timestamp": {"type": "date", "description": "Last campaign timestamp"}
                        }
                    }
                }
            },
            "shell_knocker_fields": {
                "description": "Shell knocker fields (nested under 'shell_knocker')",
                "fields": {
                    "port": {"type": "long", "description": "Shell knocker port"},
                    "protocol": {"type": "text", "description": "Shell knocker protocol"}
                }
            },
            "suspicious_admin_learnings_fields": {
                "description": "Suspicious admin learnings fields (nested)",
                "fields": {
                    "host_manages": {
                        "description": "Host manages fields",
                        "fields": {
                            "host_id": {"type": "long", "description": "Host ID"},
                            "host_key": {"type": "text", "description": "Host key"},
                            "host_name": {"type": "text", "description": "Host name"},
                            "ip": {"type": "text", "description": "IP address"},
                            "protocols": {"type": "text", "description": "Protocols"}
                        }
                    },
                    "managers_of_host": {
                        "description": "Managers of host fields",
                        "fields": {
                            "host_id": {"type": "long", "description": "Host ID"},
                            "host_key": {"type": "text", "description": "Host key"},
                            "host_name": {"type": "text", "description": "Host name"},
                            "ip": {"type": "text", "description": "IP address"},
                            "protocols": {"type": "text", "description": "Protocols"}
                        }
                    }
                }
            },
            "usage_examples": {
                "description": "Examples of how to use these fields in search queries",
                "examples": [
                    {
                        "query": "host.name:server*",
                        "description": "Find hosts with names starting with 'server'"
                    },
                    {
                        "query": "host.ip:192.168.1.*",
                        "description": "Find hosts in 192.168.1.x subnet"
                    },
                    {
                        "query": "host.is_key_asset:true",
                        "description": "Find key asset hosts"
                    },
                    {
                        "query": "host.detection_profile:*Insider*",
                        "description": "Find hosts with 'Insider Threat' detection profile"
                    },
                    {
                        "query": "host.detection_profile:External Adversaries",
                        "description": "Find hosts with 'External Adversaries' detection profile"
                    },
                    {
                        "query": "host.detection_summaries.threat:[80 TO 99]",
                        "description": "Find hosts with high-threat detections"
                    },
                    {
                        "query": "host.detection_summaries.summary.bytes_sent:[1000000 TO *]",
                        "description": "Find hosts with high data transfer"
                    },
                    {
                        "query": "host.detection_summaries.summary.beaconing:[10 TO *]",
                        "description": "Find hosts with beaconing behavior"
                    },
                    {
                        "query": "host.detection_summaries.summary.dark_ips_contacted:*",
                        "description": "Find hosts that contacted dark IPs"
                    },
                    {
                        "query": "host.sensor_name:DMZ*",
                        "description": "Find hosts detected by DMZ sensors"
                    },
                    {
                        "query": "host.ldap.department:IT",
                        "description": "Find hosts in IT department"
                    },
                    {
                        "query": "host.ldap.operating_system:Windows",
                        "description": "Find Windows hosts (exact match - most reliable)"
                    },
                    {
                        "query": "host.ldap.operating_system:Windows*",
                        "description": "Find hosts with OS starting with 'Windows' (prefix wildcard)"
                    },
                    {
                        "query": "host.ldap.operating_system:*Windows",
                        "description": "Find hosts with OS ending with 'Windows' (suffix wildcard - less reliable)"
                    },
                    {
                        "query": "host.ldap.account_disabled:true",
                        "description": "Find hosts with disabled accounts"
                    },
                    {
                        "query": "host.ldap.member_of:*Domain Controllers*",
                        "description": "Find domain controller hosts"
                    },
                    {
                        "query": "host.ldap.location:*Datacenter*",
                        "description": "Find hosts in datacenter location"
                    }
                ]
            },
            "field_access_patterns": {
                "description": "How to access nested fields in Lucene queries",
                "patterns": [
                    "Use dot notation for nested fields: host.detection_summaries.threat",
                    "Access assignment fields: host.assignment.assigned_to",
                    "Access LDAP fields: host.ldap.department, host.ldap.operating_system",
                    "Use ranges for numeric fields: host.privilege_level:[8 TO 10]",
                    "Use PREFIX wildcards for text fields: host.name:server*",
                    "Use PREFIX wildcards for LDAP fields: host.ldap.operating_system:Windows*",
                    "For OS searches, try: exact → prefix → suffix → both wildcards",
                    "Example progression: host.ldap.operating_system:Windows → Windows* → *Windows → *Windows*",
                    "Combine multiple conditions: host.is_key_asset:true AND host.detection_summaries.threat:[80 TO 99]",
                    "Combine LDAP conditions: host.ldap.department:IT AND host.ldap.account_disabled:false"
                ]
            }
        }
        
        return json.dumps(content, indent=2)
    
    async def read_resource(
        self,
        uri: str
    ) -> str:
        """
        Read the content of a Vectra search resource by URI.
        
        This tool allows Claude to access field documentation and examples
        before making API queries to ensure correct field names and syntax.
        
        Available resources:
        - vectra://search/detection-fields: Complete detection field reference with singular/plural warnings
        - vectra://search/account-fields: Complete account field reference  
        - vectra://search/host-fields: Complete host field reference
        - vectra://search/field-reference: Unified field reference for all entity types
        - vectra://search/query-examples: Practical Lucene query examples
        - vectra://search/advanced-guide: Best practices and troubleshooting tips
        
        Args:
            uri: The resource URI to read (e.g., "vectra://search/detection-fields")
            
        Returns:
            str: JSON content of the requested resource
        """
        try:
            if uri == "vectra://search/detection-fields":
                return await self.get_detection_fields_reference()
            elif uri == "vectra://search/account-fields":
                return await self.get_account_fields_reference()
            elif uri == "vectra://search/host-fields":
                return await self.get_host_fields_reference()
            elif uri == "vectra://search/query-examples":
                return await self.get_lucene_query_examples()
            elif uri == "vectra://search/advanced-guide":
                return await self.get_advanced_search_guide()
            else:
                return json.dumps({
                    "error": f"Unknown resource URI: {uri}",
                    "available_resources": [
                        "vectra://search/detection-fields",
                        "vectra://search/account-fields", 
                        "vectra://search/host-fields",
                        "vectra://search/query-examples",
                        "vectra://search/advanced-guide"
                    ]
                }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": f"Failed to read resource {uri}: {str(e)}"
            }, indent=2)
