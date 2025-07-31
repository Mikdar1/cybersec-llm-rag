"""
ATT&CK Raw Data Schema Analyzer

A standalone Streamlit application for analyzing and exploring the raw MITRE ATT&CK
data structure, schema, and relationships. This tool helps with documentation,
data modeling, and understanding the complete ATT&CK framework structure.

Features:
- Raw data fetching and display
- Schema analysis and documentation
- Object type exploration
- Relationship mapping
- Property analysis
- Export capabilities for documentation

Usage:
    streamlit run attack_data_analyzer.py
"""

import streamlit as st
import requests
import json
import pandas as pd
from collections import defaultdict, Counter
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime


class ATTACKDataAnalyzer:
    """
    Comprehensive analyzer for MITRE ATT&CK raw data structure and schema.
    
    Provides tools for exploring, analyzing, and documenting the complete
    ATT&CK framework data model including all object types, properties,
    and relationships.
    """
    
    def __init__(self):
        """Initialize the analyzer with MITRE repository URLs."""
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.enterprise_url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
        self.mobile_url = f"{self.base_url}/mobile-attack/mobile-attack.json"
        self.ics_url = f"{self.base_url}/ics-attack/ics-attack.json"
    
    def fetch_attack_data(self, dataset="enterprise"):
        """
        Fetch raw ATT&CK data from MITRE repository.
        
        Args:
            dataset (str): Dataset to fetch (enterprise, mobile, ics)
            
        Returns:
            dict: Raw ATT&CK data in JSON format
        """
        urls = {
            "enterprise": self.enterprise_url,
            "mobile": self.mobile_url,
            "ics": self.ics_url
        }
        
        try:
            with st.spinner(f"🌐 Fetching {dataset.upper()} ATT&CK data..."):
                response = requests.get(urls[dataset], timeout=30)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            st.error(f"❌ Failed to fetch {dataset} data: {e}")
            return None
    
    def analyze_object_types(self, data):
        """
        Analyze all object types in the ATT&CK data.
        
        Args:
            data (dict): Raw ATT&CK data
            
        Returns:
            dict: Object type analysis results
        """
        objects = data.get('objects', [])
        type_counts = Counter(obj.get('type', 'unknown') for obj in objects)
        
        analysis = {
            'total_objects': len(objects),
            'type_counts': dict(type_counts),
            'type_examples': {}
        }
        
        # Get example object for each type
        for obj in objects:
            obj_type = obj.get('type', 'unknown')
            if obj_type not in analysis['type_examples']:
                analysis['type_examples'][obj_type] = obj
        
        return analysis
    
    def analyze_object_schema(self, objects, obj_type):
        """
        Analyze the schema of a specific object type.
        
        Args:
            objects (list): List of ATT&CK objects
            obj_type (str): Object type to analyze
            
        Returns:
            dict: Schema analysis for the object type
        """
        filtered_objects = [obj for obj in objects if obj.get('type') == obj_type]
        
        if not filtered_objects:
            return {}
        
        # Analyze properties across all objects of this type
        all_properties = set()
        property_types = defaultdict(set)
        property_examples = {}
        property_frequency = defaultdict(int)
        
        for obj in filtered_objects:
            for key, value in obj.items():
                all_properties.add(key)
                property_frequency[key] += 1
                
                # Determine property type
                if isinstance(value, list):
                    if value:  # Non-empty list
                        element_type = type(value[0]).__name__
                        property_types[key].add(f"list[{element_type}]")
                    else:
                        property_types[key].add("list[empty]")
                else:
                    property_types[key].add(type(value).__name__)
                
                # Store example if not already stored
                if key not in property_examples:
                    property_examples[key] = value
        
        return {
            'total_objects': len(filtered_objects),
            'properties': sorted(all_properties),
            'property_types': {k: list(v) for k, v in property_types.items()},
            'property_examples': property_examples,
            'property_frequency': dict(property_frequency),
            'sample_object': filtered_objects[0] if filtered_objects else None
        }
    
    def analyze_relationships(self, objects):
        """
        Analyze relationship patterns in ATT&CK data.
        
        Args:
            objects (list): List of ATT&CK objects
            
        Returns:
            dict: Relationship analysis results
        """
        relationships = [obj for obj in objects if obj.get('type') == 'relationship']
        
        if not relationships:
            return {}
        
        # Analyze relationship types
        rel_types = Counter(rel.get('relationship_type') for rel in relationships)
        
        # Analyze source and target patterns
        source_types = Counter()
        target_types = Counter()
        
        for rel in relationships:
            source_ref = rel.get('source_ref', '')
            target_ref = rel.get('target_ref', '')
            
            # Extract object type from reference (format: type--uuid)
            if '--' in source_ref:
                source_type = source_ref.split('--')[0]
                source_types[source_type] += 1
            
            if '--' in target_ref:
                target_type = target_ref.split('--')[0]
                target_types[target_type] += 1
        
        return {
            'total_relationships': len(relationships),
            'relationship_types': dict(rel_types),
            'source_types': dict(source_types),
            'target_types': dict(target_types),
            'sample_relationship': relationships[0] if relationships else None
        }
    
    def export_schema_documentation(self, analysis_results, dataset_name):
        """
        Export schema analysis as documentation.
        
        Args:
            analysis_results (dict): Analysis results
            dataset_name (str): Name of the dataset
            
        Returns:
            str: Formatted documentation
        """
        doc = f"""# MITRE ATT&CK {dataset_name.upper()} Dataset Schema Analysis

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview
- **Total Objects**: {analysis_results.get('total_objects', 0):,}
- **Object Types**: {len(analysis_results.get('type_counts', {})):,}

## Object Type Distribution

"""
        
        for obj_type, count in analysis_results.get('type_counts', {}).items():
            percentage = (count / analysis_results.get('total_objects', 1)) * 100
            doc += f"- **{obj_type}**: {count:,} objects ({percentage:.1f}%)\n"
        
        doc += "\n## Detailed Schema Information\n\n"
        doc += "*(Use the interactive analyzer for detailed property schemas)*\n"
        
        return doc


def main():
    """Main application interface for ATT&CK data analysis."""
    
    # Configure page
    st.set_page_config(
        page_title="ATT&CK Data Schema Analyzer",
        page_icon="🔬",
        layout="wide"
    )
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8fafc;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔬 MITRE ATT&CK Data Schema Analyzer</h1>
        <p>Explore and analyze the raw ATT&CK data structure for documentation and research</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize analyzer
    analyzer = ATTACKDataAnalyzer()
    
    # Sidebar controls
    st.sidebar.header("🎛️ Analysis Controls")
    
    # Dataset selection
    dataset = st.sidebar.selectbox(
        "Select ATT&CK Dataset",
        ["enterprise", "mobile", "ics"],
        help="Choose which ATT&CK dataset to analyze"
    )
    
    # Analysis mode
    analysis_mode = st.sidebar.radio(
        "Analysis Mode",
        ["Overview", "Object Types", "Schema Deep Dive", "Relationships", "Export Documentation"]
    )
    
    # Fetch data
    if 'attack_data' not in st.session_state or st.sidebar.button("🔄 Refresh Data"):
        st.session_state.attack_data = analyzer.fetch_attack_data(dataset)
        st.session_state.dataset_name = dataset
    
    if not st.session_state.get('attack_data'):
        st.error("❌ No data available. Please try refreshing.")
        return
    
    data = st.session_state.attack_data
    if not data:
        st.error("❌ Invalid data format. Please refresh the data.")
        return
        
    objects = data.get('objects', [])
    
    # Main content based on analysis mode
    if analysis_mode == "Overview":
        render_overview(analyzer, data, objects)
    
    elif analysis_mode == "Object Types":
        render_object_types(analyzer, data, objects)
    
    elif analysis_mode == "Schema Deep Dive":
        render_schema_deep_dive(analyzer, objects)
    
    elif analysis_mode == "Relationships":
        render_relationships(analyzer, objects)
    
    elif analysis_mode == "Export Documentation":
        render_export_documentation(analyzer, data, st.session_state.dataset_name)


def render_overview(analyzer, data, objects):
    """Render the overview analysis."""
    st.header("📊 Dataset Overview")
    
    # Basic statistics
    analysis = analyzer.analyze_object_types(data)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Objects", f"{analysis['total_objects']:,}")
    
    with col2:
        st.metric("Object Types", len(analysis['type_counts']))
    
    with col3:
        st.metric("Dataset Info", data.get('spec_version', 'Unknown'))
    
    with col4:
        st.metric("Data ID", data.get('id', 'Unknown')[:8] + "...")
    
    # Object type distribution chart
    st.subheader("🎯 Object Type Distribution")
    
    df = pd.DataFrame(list(analysis['type_counts'].items()), columns=['Type', 'Count'])
    df = df.sort_values('Count', ascending=False)
    
    fig = px.bar(df, x='Type', y='Count', title="ATT&CK Object Types by Count")
    fig.update_layout(xaxis_tickangle=45)
    st.plotly_chart(fig, use_container_width=True)
    
    # Pie chart
    col1, col2 = st.columns(2)
    
    with col1:
        fig_pie = px.pie(df, values='Count', names='Type', title="Object Type Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        st.subheader("📋 Object Type Summary")
        for obj_type, count in df.head(10).values:
            percentage = (count / analysis['total_objects']) * 100
            st.write(f"**{obj_type}**: {count:,} ({percentage:.1f}%)")


def render_object_types(analyzer, data, objects):
    """Render object type analysis."""
    st.header("🎯 Object Type Analysis")
    
    analysis = analyzer.analyze_object_types(data)
    
    # Object type selector
    selected_type = st.selectbox(
        "Select Object Type to Analyze",
        sorted(analysis['type_counts'].keys())
    )
    
    if selected_type:
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader(f"📊 {selected_type} Statistics")
            st.metric("Count", analysis['type_counts'][selected_type])
            
            percentage = (analysis['type_counts'][selected_type] / analysis['total_objects']) * 100
            st.metric("Percentage", f"{percentage:.2f}%")
        
        with col2:
            st.subheader(f"🔍 Sample {selected_type} Object")
            sample_obj = analysis['type_examples'][selected_type]
            st.json(sample_obj, expanded=False)
        
        # Show all objects of this type
        st.subheader(f"📝 All {selected_type} Objects")
        type_objects = [obj for obj in objects if obj.get('type') == selected_type]
        
        if type_objects:
            # Create a summary table
            summary_data = []
            for obj in type_objects[:100]:  # Limit for performance
                summary_data.append({
                    'ID': obj.get('id', '')[:20] + '...',
                    'Name': obj.get('name', 'N/A')[:50],
                    'Created': obj.get('created', 'N/A')[:10],
                    'Modified': obj.get('modified', 'N/A')[:10]
                })
            
            df = pd.DataFrame(summary_data)
            st.dataframe(df, use_container_width=True)
            
            if len(type_objects) > 100:
                st.info(f"Showing first 100 of {len(type_objects)} {selected_type} objects")


def render_schema_deep_dive(analyzer, objects):
    """Render detailed schema analysis."""
    st.header("🔬 Schema Deep Dive")
    
    # Get unique object types
    object_types = sorted(set(obj.get('type') for obj in objects))
    
    selected_type = st.selectbox("Select Object Type for Schema Analysis", object_types)
    
    if selected_type:
        schema_analysis = analyzer.analyze_object_schema(objects, selected_type)
        
        if schema_analysis:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.subheader(f"📊 {selected_type} Schema Summary")
                st.metric("Total Objects", schema_analysis['total_objects'])
                st.metric("Unique Properties", len(schema_analysis['properties']))
                
                # Property frequency chart
                freq_data = schema_analysis['property_frequency']
                df_freq = pd.DataFrame(list(freq_data.items()), columns=['Property', 'Frequency'])
                df_freq = df_freq.sort_values('Frequency', ascending=False)
                
                fig = px.bar(df_freq.head(15), x='Frequency', y='Property', 
                           orientation='h', title="Property Frequency")
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader(f"🔍 Property Details")
                
                selected_property = st.selectbox(
                    "Select Property to Examine", 
                    sorted(schema_analysis['properties'])
                )
                
                if selected_property:
                    prop_types = schema_analysis['property_types'].get(selected_property, [])
                    prop_example = schema_analysis['property_examples'].get(selected_property)
                    prop_freq = schema_analysis['property_frequency'].get(selected_property, 0)
                    
                    st.write(f"**Property**: `{selected_property}`")
                    st.write(f"**Types**: {', '.join(prop_types)}")
                    st.write(f"**Frequency**: {prop_freq}/{schema_analysis['total_objects']} objects")
                    
                    st.write("**Example Value**:")
                    if isinstance(prop_example, (dict, list)):
                        st.json(prop_example)
                    else:
                        st.code(str(prop_example))
            
            # Full schema table
            st.subheader(f"📋 Complete {selected_type} Schema")
            
            schema_table = []
            for prop in sorted(schema_analysis['properties']):
                prop_types = schema_analysis['property_types'].get(prop, [])
                prop_freq = schema_analysis['property_frequency'].get(prop, 0)
                coverage = (prop_freq / schema_analysis['total_objects']) * 100
                
                schema_table.append({
                    'Property': prop,
                    'Types': ', '.join(prop_types),
                    'Frequency': prop_freq,
                    'Coverage (%)': f"{coverage:.1f}%"
                })
            
            df_schema = pd.DataFrame(schema_table)
            st.dataframe(df_schema, use_container_width=True)


def render_relationships(analyzer, objects):
    """Render relationship analysis."""
    st.header("🔗 Relationship Analysis")
    
    rel_analysis = analyzer.analyze_relationships(objects)
    
    if not rel_analysis:
        st.warning("No relationship objects found in the dataset.")
        return
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Relationships", rel_analysis['total_relationships'])
    
    with col2:
        st.metric("Relationship Types", len(rel_analysis['relationship_types']))
    
    with col3:
        st.metric("Source Types", len(rel_analysis['source_types']))
    
    # Relationship type distribution
    st.subheader("📊 Relationship Types")
    rel_types_df = pd.DataFrame(
        list(rel_analysis['relationship_types'].items()), 
        columns=['Relationship Type', 'Count']
    ).sort_values('Count', ascending=False)
    
    fig = px.bar(rel_types_df, x='Relationship Type', y='Count', 
                title="Relationship Types Distribution")
    fig.update_layout(xaxis_tickangle=45)
    st.plotly_chart(fig, use_container_width=True)
    
    # Source and target analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📤 Source Object Types")
        source_df = pd.DataFrame(
            list(rel_analysis['source_types'].items()), 
            columns=['Type', 'Count']
        ).sort_values('Count', ascending=False)
        st.dataframe(source_df)
    
    with col2:
        st.subheader("📥 Target Object Types")
        target_df = pd.DataFrame(
            list(rel_analysis['target_types'].items()), 
            columns=['Type', 'Count']
        ).sort_values('Count', ascending=False)
        st.dataframe(target_df)
    
    # Sample relationship
    st.subheader("🔍 Sample Relationship Object")
    if rel_analysis.get('sample_relationship'):
        st.json(rel_analysis['sample_relationship'])


def render_export_documentation(analyzer, data, dataset_name):
    """Render documentation export interface."""
    st.header("📄 Export Documentation")
    
    analysis = analyzer.analyze_object_types(data)
    
    # Generate documentation
    documentation = analyzer.export_schema_documentation(analysis, dataset_name)
    
    st.subheader("📋 Generated Documentation Preview")
    st.markdown(documentation)
    
    # Download button
    st.download_button(
        label="📥 Download Schema Documentation",
        data=documentation,
        file_name=f"attack_{dataset_name}_schema_analysis.md",
        mime="text/markdown"
    )
    
    # Export raw data
    st.subheader("📊 Export Raw Analysis Data")
    
    if st.button("Generate JSON Export"):
        export_data = {
            'dataset': dataset_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'overview': analysis,
            'raw_data_summary': {
                'total_objects': len(data.get('objects', [])),
                'spec_version': data.get('spec_version'),
                'data_id': data.get('id')
            }
        }
        
        st.download_button(
            label="📥 Download Analysis Data (JSON)",
            data=json.dumps(export_data, indent=2),
            file_name=f"attack_{dataset_name}_analysis.json",
            mime="application/json"
        )


if __name__ == "__main__":
    main()
