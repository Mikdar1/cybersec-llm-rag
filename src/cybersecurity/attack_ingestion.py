"""
MITRE ATT&CK Knowledge Base Data Ingestion Module

This module handles the comprehensive ingestion of MITRE ATT&CK framework data
into a Neo4j graph database. It processes all major ATT&CK object types including
techniques, tactics, malware, threat groups, tools, mitigations, data sources,
data components, campaigns, and their relationships.

Features:
- Fetches latest ATT&CK data from MITRE's official repository
- Processes all ATT&CK object types with proper data normalization
- Creates comprehensive graph relationships in Neo4j
- Handles both embedded and standalone relationship objects
- Provides detailed ingestion statistics and error handling

Classes:
    ATTACKDataIngester: Main class for ATT&CK data ingestion operations
"""

import requests
import streamlit as st


class ATTACKDataIngester:
    """
    Handles comprehensive MITRE ATT&CK framework data ingestion.
    
    This class provides methods to fetch, process, and store ATT&CK data
    from MITRE's official repository into a Neo4j graph database with
    full relationship mapping and data integrity.
    
    Attributes:
        base_url (str): Base URL for MITRE CTI repository
        enterprise_url (str): Direct URL to enterprise ATT&CK data
    """
    
    def __init__(self):
        """Initialize the ATT&CK data ingester with MITRE repository URLs."""
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.enterprise_url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
    def fetch_attack_data(self):
        """
        Fetch ATT&CK data from MITRE's official repository.
        
        Returns:
            dict: Complete ATT&CK framework data in JSON format
            
        Raises:
            Exception: If data fetching fails due to network or server issues
        """
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to fetch ATT&CK data: {str(e)}")
    
    def process_attack_objects(self, attack_data):
        """
        Process all ATT&CK objects and convert them to graph-ready data.
        
        Processes various ATT&CK object types including techniques, malware,
        threat groups, tools, mitigations, data sources, campaigns, and
        relationships. Creates nodes and relationships suitable for Neo4j storage.
        
        Args:
            attack_data (dict): Raw ATT&CK data from MITRE repository
            
        Returns:
            dict: Processed graph data with nodes, relationships, and statistics
        """
        # Initialize data structures and statistics
        nodes = []
        relationships = []
        stats = {
            'techniques': 0,
            'malware': 0,
            'threat_groups': 0,
            'tools': 0,
            'tactics': 0,
            'mitigations': 0,
            'data_sources': 0,
            'data_components': 0,
            'campaigns': 0,
            'relationships': 0,
            'other': 0
        }
        
        # Process each object in the ATT&CK dataset
        objects = attack_data.get('objects', [])
        
        for obj in objects:
            obj_type = obj.get('type', '')
            obj_id = obj.get('id', '')
            
            # Process ATT&CK techniques (attack-pattern objects)
            if obj_type == 'attack-pattern':
                technique_data = self._process_technique(obj)
                nodes.append(technique_data)
                relationships.extend(technique_data['relationships'])
                
                # Add tactic nodes for this technique
                for tactic_data in technique_data.get('tactics', []):
                    nodes.append(tactic_data)
                    stats['tactics'] += 1
                
                stats['techniques'] += 1
                
            # Process malware families
            elif obj_type == 'malware':
                malware_data = self._process_malware(obj)
                nodes.append(malware_data)
                relationships.extend(malware_data['relationships'])
                stats['malware'] += 1
                
            # Process threat groups and APTs
            elif obj_type == 'intrusion-set':
                group_data = self._process_threat_group(obj)
                nodes.append(group_data)
                relationships.extend(group_data['relationships'])
                stats['threat_groups'] += 1
                
            # Process tools and software
            elif obj_type == 'tool':
                tool_data = self._process_tool(obj)
                nodes.append(tool_data)
                relationships.extend(tool_data['relationships'])
                stats['tools'] += 1
                
            # Process mitigations and countermeasures
            elif obj_type == 'course-of-action':
                mitigation_data = self._process_mitigation(obj)
                nodes.append(mitigation_data)
                relationships.extend(mitigation_data['relationships'])
                stats['mitigations'] += 1
                
            # Process data sources
            elif obj_type == 'x-mitre-data-source':
                data_source_data = self._process_data_source(obj)
                nodes.append(data_source_data)
                relationships.extend(data_source_data['relationships'])
                stats['data_sources'] += 1
                
            # Process data components
            elif obj_type == 'x-mitre-data-component':
                data_component_data = self._process_data_component(obj)
                nodes.append(data_component_data)
                relationships.extend(data_component_data['relationships'])
                stats['data_components'] += 1
                
            # Process campaigns
            elif obj_type == 'campaign':
                campaign_data = self._process_campaign(obj)
                nodes.append(campaign_data)
                relationships.extend(campaign_data['relationships'])
                stats['campaigns'] += 1
                
            # Process standalone relationship objects
            elif obj_type == 'relationship':
                rel_data = self._process_relationship(obj)
                if rel_data:
                    relationships.append(rel_data)
                    stats['relationships'] += 1
            else:
                stats['other'] += 1
        
        # Display comprehensive ingestion statistics
        st.info(f"""
        📊 **ATT&CK Data Ingestion Summary:**
        - 🎯 **Techniques**: {stats['techniques']} (T-codes)
        - 🦠 **Malware**: {stats['malware']} families
        - 👥 **Threat Groups**: {stats['threat_groups']} (APTs)
        - 🔧 **Tools**: {stats['tools']} and software
        - 🛡️ **Mitigations**: {stats['mitigations']} (M-codes)
        - 📊 **Data Sources**: {stats['data_sources']}
        - 🔍 **Data Components**: {stats['data_components']}
        - 🎭 **Campaigns**: {stats['campaigns']}
        - 🔗 **Relationships**: {stats['relationships']}
        - ❓ **Other Objects**: {stats['other']}
        """)
        
        return {"nodes": nodes, "relationships": relationships, "stats": stats}
    
    def _process_technique(self, obj):
        """
        Process ATT&CK technique objects (attack-pattern type).
        
        Extracts technique information including ID, name, tactics, platforms,
        data sources, and other MITRE-specific attributes. Creates tactic nodes
        and relationships for comprehensive graph representation.
        
        Args:
            obj (dict): Raw technique object from ATT&CK data
            
        Returns:
            dict: Processed technique data with node and relationship information
        """
        # Extract technique identification
        external_references = obj.get('external_references', [])
        technique_id = ''
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id', '')
                break
        if not technique_id:
            technique_id = obj.get('id', '')
            
        # Extract basic properties
        name = obj.get('name', '')
        description = obj.get('description', '')
        
        # Extract tactic associations
        kill_chain_phases = obj.get('kill_chain_phases', [])
        tactics = [phase.get('phase_name', '') for phase in kill_chain_phases]
        
        # Extract platform and data source information
        platforms = obj.get('x_mitre_platforms', [])
        data_sources_raw = obj.get('x_mitre_data_sources', [])
        
        # Normalize data sources for Neo4j compatibility
        if data_sources_raw and isinstance(data_sources_raw[0], dict):
            data_sources = [ds.get('data_source_name', str(ds)) if isinstance(ds, dict) else str(ds) for ds in data_sources_raw]
        else:
            data_sources = [str(ds) for ds in data_sources_raw] if data_sources_raw else []
            
        # Extract additional MITRE-specific attributes
        permissions_required = obj.get('x_mitre_permissions_required', [])
        is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
        kill_chain_phase_names = [f"{phase.get('kill_chain_name', '')}: {phase.get('phase_name', '')}" for phase in kill_chain_phases]
        
        # Create technique node structure
        node = {
            "id": obj.get('id'),
            "type": "Technique",
            "properties": {
                "technique_id": technique_id,
                "name": name,
                "description": description[:500],  # Truncated for display
                "tactics": tactics,
                "platforms": platforms,
                "data_sources": data_sources,
                "kill_chain_phases": kill_chain_phase_names,
                "permissions_required": permissions_required,
                "is_subtechnique": is_subtechnique,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description  # Complete description
            }
        }
        
        # Initialize relationship and tactic node collections
        relationships = []
        tactic_nodes = []
        
        # Create tactic nodes and relationships for each associated tactic
        for tactic in tactics:
            tactic_id = f"tactic_{tactic}"
            
            # Create relationship between technique and tactic
            relationships.append({
                "source": obj.get('id'),
                "target": tactic_id,
                "type": "BELONGS_TO_TACTIC",
                "properties": {"tactic_name": tactic}
            })
            
            # Create corresponding tactic node
            tactic_nodes.append({
                "node": {
                    "id": tactic_id,
                    "type": "Tactic",
                    "properties": {
                        "name": tactic,
                        "description": f"MITRE ATT&CK Tactic: {tactic}",
                        "created": obj.get('created', ''),
                        "modified": obj.get('modified', '')
                    }
                },
                "relationships": []
            })
        
        return {"node": node, "relationships": relationships, "tactics": tactic_nodes}
    
    def _process_malware(self, obj):
        """
        Process malware family objects.
        
        Args:
            obj (dict): Raw malware object from ATT&CK data
            
        Returns:
            dict: Processed malware data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        labels = obj.get('labels', [])
        platforms = obj.get('x_mitre_platforms', [])
        
        node = {
            "id": obj.get('id'),
            "type": "Malware",
            "properties": {
                "name": name,
                "description": description[:500],
                "labels": labels,
                "platforms": platforms,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_threat_group(self, obj):
        """
        Process threat group (intrusion-set) objects.
        
        Args:
            obj (dict): Raw threat group object from ATT&CK data
            
        Returns:
            dict: Processed threat group data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        aliases = obj.get('aliases', [])
        
        # Extract group identification (G-code)
        external_references = obj.get('external_references', [])
        group_id = ''
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                group_id = ref.get('external_id', '')
                break
        
        node = {
            "id": obj.get('id'),
            "type": "ThreatGroup",
            "properties": {
                "group_id": group_id,
                "name": name,
                "description": description[:500],
                "aliases": aliases,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_tool(self, obj):
        """
        Process tool and software objects.
        
        Args:
            obj (dict): Raw tool object from ATT&CK data
            
        Returns:
            dict: Processed tool data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        labels = obj.get('labels', [])
        platforms = obj.get('x_mitre_platforms', [])
        
        # Extract tool identification (S-code)
        external_references = obj.get('external_references', [])
        tool_id = ''
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                tool_id = ref.get('external_id', '')
                break
        
        node = {
            "id": obj.get('id'),
            "type": "Tool",
            "properties": {
                "tool_id": tool_id,
                "name": name,
                "description": description[:500],
                "labels": labels,
                "platforms": platforms,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_mitigation(self, obj):
        """
        Process mitigation (course-of-action) objects.
        
        Args:
            obj (dict): Raw mitigation object from ATT&CK data
            
        Returns:
            dict: Processed mitigation data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        external_references = obj.get('external_references', [])
        mitigation_id = ''
        
        # Extract mitigation identification (M-code)
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                mitigation_id = ref.get('external_id', '')
                break
        
        node = {
            "id": obj.get('id'),
            "type": "Mitigation",
            "properties": {
                "mitigation_id": mitigation_id,
                "name": name,
                "description": description[:500],
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_data_source(self, obj):
        """
        Process data source objects.
        
        Args:
            obj (dict): Raw data source object from ATT&CK data
            
        Returns:
            dict: Processed data source data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        platforms = obj.get('x_mitre_platforms', [])
        
        node = {
            "id": obj.get('id'),
            "type": "DataSource",
            "properties": {
                "name": name,
                "description": description[:500],
                "platforms": platforms,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_data_component(self, obj):
        """
        Process data component objects.
        
        Args:
            obj (dict): Raw data component object from ATT&CK data
            
        Returns:
            dict: Processed data component data with node and relationship information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        data_source_ref = obj.get('x_mitre_data_source_ref', '')
        
        node = {
            "id": obj.get('id'),
            "type": "DataComponent",
            "properties": {
                "name": name,
                "description": description[:500],
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        # Create relationship to parent data source if reference exists
        relationships = []
        if data_source_ref:
            relationships.append({
                "source": obj.get('id'),
                "target": data_source_ref,
                "type": "BELONGS_TO_DATA_SOURCE",
                "properties": {}
            })
        
        return {"node": node, "relationships": relationships}
    
    def _process_campaign(self, obj):
        """
        Process campaign objects.
        
        Args:
            obj (dict): Raw campaign object from ATT&CK data
            
        Returns:
            dict: Processed campaign data with node information
        """
        name = obj.get('name', '')
        description = obj.get('description', '')
        aliases = obj.get('aliases', [])
        first_seen = obj.get('first_seen', '')
        last_seen = obj.get('last_seen', '')
        
        node = {
            "id": obj.get('id'),
            "type": "Campaign",
            "properties": {
                "name": name,
                "description": description[:500],
                "aliases": aliases,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "created": obj.get('created', ''),
                "modified": obj.get('modified', ''),
                "full_description": description
            }
        }
        
        return {"node": node, "relationships": []}
    
    def _process_relationship(self, obj):
        """
        Process standalone relationship objects.
        
        Args:
            obj (dict): Raw relationship object from ATT&CK data
            
        Returns:
            dict: Processed relationship data or None if invalid
        """
        source_ref = obj.get('source_ref', '')
        target_ref = obj.get('target_ref', '')
        relationship_type = obj.get('relationship_type', '')
        
        if source_ref and target_ref and relationship_type:
            return {
                "source": source_ref,
                "target": target_ref,
                "type": relationship_type.upper().replace('-', '_'),
                "properties": {
                    "description": obj.get('description', ''),
                    "created": obj.get('created', '')
                }
            }
        
        return None
    
    def store_in_neo4j(self, graph, nodes_data, relationships_data=None):
        """
        Store processed ATT&CK data in Neo4j database.
        
        Creates nodes and relationships in Neo4j with proper error handling
        and transaction management. Processes both node-embedded relationships
        and standalone relationship objects.
        
        Args:
            graph: Neo4j database connection object
            nodes_data (list): Processed node data with embedded relationships
            relationships_data (list, optional): Standalone relationship data
            
        Returns:
            tuple: (nodes_stored, relationships_stored) counts
        """
        if not graph:
            print("No database connection available")
            return 0, 0
        
        nodes_stored = 0
        relationships_stored = 0
        
        with graph.driver.session() as session:
            # Process and store all nodes
            for item in nodes_data:
                node = item.get('node')
                if node:
                    node_type = node['type']
                    node_id = node['id']
                    props = node['properties']
                    
                    try:
                        # Generate appropriate Cypher query based on node type
                        if node_type == 'Technique':
                            query = """
                            MERGE (t:Technique {id: $id})
                            SET t.technique_id = $technique_id,
                                t.name = $name,
                                t.description = $description,
                                t.tactics = $tactics,
                                t.platforms = $platforms,
                                t.data_sources = $data_sources,
                                t.kill_chain_phases = $kill_chain_phases,
                                t.permissions_required = $permissions_required,
                                t.is_subtechnique = $is_subtechnique,
                                t.created = $created,
                                t.modified = $modified,
                                t.full_description = $full_description
                            """
                        elif node_type == 'Malware':
                            query = """
                            MERGE (m:Malware {id: $id})
                            SET m.name = $name,
                                m.description = $description,
                                m.labels = $labels,
                                m.platforms = $platforms,
                                m.created = $created,
                                m.modified = $modified,
                                m.full_description = $full_description
                            """
                        elif node_type == 'ThreatGroup':
                            query = """
                            MERGE (g:ThreatGroup {id: $id})
                            SET g.group_id = $group_id,
                                g.name = $name,
                                g.description = $description,
                                g.aliases = $aliases,
                                g.created = $created,
                                g.modified = $modified,
                                g.full_description = $full_description
                            """
                        elif node_type == 'Tool':
                            query = """
                            MERGE (t:Tool {id: $id})
                            SET t.tool_id = $tool_id,
                                t.name = $name,
                                t.description = $description,
                                t.labels = $labels,
                                t.platforms = $platforms,
                                t.created = $created,
                                t.modified = $modified,
                                t.full_description = $full_description
                            """
                        elif node_type == 'Mitigation':
                            query = """
                            MERGE (m:Mitigation {id: $id})
                            SET m.mitigation_id = $mitigation_id,
                                m.name = $name,
                                m.description = $description,
                                m.created = $created,
                                m.modified = $modified,
                                m.full_description = $full_description
                            """
                        elif node_type == 'DataSource':
                            query = """
                            MERGE (ds:DataSource {id: $id})
                            SET ds.name = $name,
                                ds.description = $description,
                                ds.platforms = $platforms,
                                ds.created = $created,
                                ds.modified = $modified,
                                ds.full_description = $full_description
                            """
                        elif node_type == 'DataComponent':
                            query = """
                            MERGE (dc:DataComponent {id: $id})
                            SET dc.name = $name,
                                dc.description = $description,
                                dc.created = $created,
                                dc.modified = $modified,
                                dc.full_description = $full_description
                            """
                        elif node_type == 'Campaign':
                            query = """
                            MERGE (c:Campaign {id: $id})
                            SET c.name = $name,
                                c.description = $description,
                                c.aliases = $aliases,
                                c.first_seen = $first_seen,
                                c.last_seen = $last_seen,
                                c.created = $created,
                                c.modified = $modified,
                                c.full_description = $full_description
                            """
                        elif node_type == 'Tactic':
                            query = """
                            MERGE (t:Tactic {id: $id})
                            SET t.name = $name,
                                t.description = $description,
                                t.created = $created,
                                t.modified = $modified
                            """
                        else:
                            continue
                        
                        session.run(query, id=node_id, **props)
                        nodes_stored += 1
                    except Exception as e:
                        print(f"Error storing node {node_id}: {e}")
                        continue
            
            # Process node-embedded relationships
            for item in nodes_data:
                relationships = item.get('relationships', [])
                for rel in relationships:
                    try:
                        rel_query = """
                        MATCH (source {id: $source_id})
                        MATCH (target {id: $target_id})
                        MERGE (source)-[r:""" + rel['type'] + """]->(target)
                        SET r += $properties
                        """
                        session.run(
                            rel_query,
                            source_id=rel['source'],
                            target_id=rel['target'],
                            properties=rel.get('properties', {})
                        )
                        relationships_stored += 1
                    except Exception as e:
                        print(f"Error storing node relationship {rel}: {e}")
                        continue
            
            # Process standalone relationships if provided
            if relationships_data:
                for rel in relationships_data:
                    try:
                        rel_query = """
                        MATCH (source {id: $source_id})
                        MATCH (target {id: $target_id})
                        MERGE (source)-[r:""" + rel['type'] + """]->(target)
                        SET r += $properties
                        """
                        session.run(
                            rel_query,
                            source_id=rel['source'],
                            target_id=rel['target'],
                            properties=rel.get('properties', {})
                        )
                        relationships_stored += 1
                    except Exception as e:
                        print(f"Error storing standalone relationship {rel}: {e}")
                        continue
        
        return nodes_stored, relationships_stored
    
    def ingest_attack_data(self, graph):
        """
        Main orchestration method for ATT&CK data ingestion.
        
        Coordinates the complete ingestion process including data fetching,
        processing, and storage in Neo4j with comprehensive error handling
        and user feedback through Streamlit interface.
        
        Args:
            graph: Neo4j database connection object
            
        Returns:
            tuple: (success_boolean, status_message)
        """
        try:
            # Step 1: Fetch latest ATT&CK data from MITRE repository
            with st.spinner("🌐 Fetching ATT&CK data from MITRE repository..."):
                attack_data = self.fetch_attack_data()
                st.success("✅ Successfully fetched ATT&CK data from MITRE")
            
            # Step 2: Process and normalize all ATT&CK objects
            with st.spinner("⚙️ Processing ATT&CK objects and relationships..."):
                graph_data = self.process_attack_objects(attack_data)
                st.success(f"✅ Processed {len(graph_data['nodes'])} nodes and {len(graph_data['relationships'])} relationships")
            
            # Step 3: Store processed data in Neo4j database
            with st.spinner("💾 Storing data in Neo4j database..."):
                nodes_stored, relationships_stored = self.store_in_neo4j(
                    graph, 
                    graph_data['nodes'], 
                    graph_data['relationships']
                )
                st.success(f"✅ Successfully stored {nodes_stored} nodes and {relationships_stored} relationships in Neo4j")
            
            return True, f"Successfully ingested ATT&CK data: {nodes_stored} nodes, {relationships_stored} relationships"
            
        except Exception as e:
            return False, str(e)
