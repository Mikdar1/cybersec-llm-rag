"""
Knowledge Base Initialization and Setup Utilities Module

This module handles the initialization and setup of the MITRE ATT&CK knowledge
base in Neo4j. It manages data ingestion, validation, and ensures the database
is properly populated with the latest ATT&CK framework data.

Features:
- Automatic knowledge base initialization
- Data existence validation
- Session state management
- Progress tracking and user feedback
- Error handling and recovery

Functions:
    initialize_knowledge_base: Main initialization orchestrator
    refresh_knowledge_base: Force refresh of ATT&CK data
"""

import streamlit as st
from src.cybersecurity.attack_ingestion import ATTACKDataIngester
from src.knowledge_base.database import clear_knowledge_base


def initialize_knowledge_base(graph):
    """
    Initialize the ATT&CK knowledge base with comprehensive data validation.
    
    Checks for existing data and performs initialization only when necessary.
    Manages session state to prevent redundant initialization attempts and
    provides detailed progress feedback to users.
    
    Args:
        graph: Neo4j database connection instance
    """
    # Skip if already initialized in current session
    if st.session_state.knowledge_base_initialized:
        return
    
    with st.spinner("🔄 Initializing MITRE ATT&CK knowledge base..."):
        try:
            # Validate existing data in Neo4j database
            check_query = "MATCH (n) RETURN count(n) as count"
            result = graph.query(check_query)
            existing_count = result[0]['count'] if result else 0
            
            if existing_count > 0:
                st.info(f"📊 Knowledge base already contains {existing_count:,} nodes. Skipping initialization.")
                st.session_state.knowledge_base_initialized = True
                return
            
            # Initialize and configure ATT&CK data ingester
            st.info("🚀 Starting fresh ATT&CK data ingestion...")
            ingester = ATTACKDataIngester()
            
            # Execute comprehensive data ingestion process
            success, message = ingester.ingest_attack_data(graph)
            
            if success:
                st.success(f"✅ {message}")
                st.session_state.knowledge_base_initialized = True
                st.balloons()  # Celebrate successful initialization
            else:
                st.error(f"❌ Failed to initialize knowledge base: {message}")
                
        except Exception as e:
            st.error(f"❌ Error during knowledge base initialization: {str(e)}")
            st.info("💡 Please check your Neo4j connection and try again.")


def refresh_knowledge_base(graph):
    """
    Force refresh of the ATT&CK knowledge base with latest data.
    
    Clears existing data and performs complete re-ingestion of the
    MITRE ATT&CK framework. Use when data updates are needed.
    
    Args:
        graph: Neo4j database connection instance
        
    Returns:
        tuple: (success_boolean, status_message)
    """
    try:
        with st.spinner("🗑️ Clearing existing knowledge base..."):
            clear_knowledge_base(graph)
            
        with st.spinner("🔄 Ingesting latest ATT&CK data..."):
            # Reset session state for fresh initialization
            st.session_state.knowledge_base_initialized = False
            
            # Initialize and run data ingestion
            ingester = ATTACKDataIngester()
            success, message = ingester.ingest_attack_data(graph)
            
            if success:
                st.session_state.knowledge_base_initialized = True
                return True, f"Successfully refreshed knowledge base: {message}"
            else:
                return False, f"Failed to refresh knowledge base: {message}"
                
    except Exception as e:
        return False, f"Error during knowledge base refresh: {str(e)}"


def reingest_attack_data(graph):
    """
    Legacy function for re-ingesting ATT&CK data.
    
    Provides backward compatibility for existing code that uses
    the older reingest function name. Delegates to refresh_knowledge_base.
    
    Args:
        graph: Neo4j database connection instance
        
    Returns:
        bool: Success status of re-ingestion operation
    """
    try:
        # Use the updated refresh function for consistency
        success, message = refresh_knowledge_base(graph)
        
        if success:
            st.success(f"✅ {message}")
            return True
        else:
            st.error(f"❌ {message}")
            return False
            
    except Exception as e:
        st.error(f"❌ Error during data re-ingestion: {str(e)}")
        return False
