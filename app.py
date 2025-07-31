"""
Cybersecurity Multi-Framework Assistant

A Streamlit application that provides an interactive interface for exploring
and chatting with multiple cybersecurity frameworks stored in Neo4j.

Features:
- Interactive chat with comprehensive cybersecurity knowledge base
- Multi-framework data exploration (ATT&CK, CIS, NIST, HIPAA, FFIEC, PCI DSS)
- Graph-based cybersecurity intelligence
- Real-time data ingestion from multiple authoritative sources
- Cross-framework relationship analysis

Supported Frameworks:
- MITRE ATT&CK: Threat tactics, techniques, and procedures
- CIS Controls: Critical security controls and safeguards
- NIST CSF: Cybersecurity Framework functions and subcategories
- HIPAA: Healthcare regulatory compliance requirements
- FFIEC: Financial institution examination procedures
- PCI DSS: Payment card industry security standards

Usage:
    streamlit run app.py
"""

import streamlit as st

# Import application modules
from src.knowledge_base.database import create_graph_connection
from src.api.llm_service import get_llm
from src.utils.initialization import initialize_knowledge_base
from src.web.ui import get_css
from src.web.components import chat_tab, knowledge_base_tab, sidebar_components


def configure_page():
    """Configure Streamlit page settings and styling."""
    st.set_page_config(
        page_title="Cybersecurity Multi-Framework Assistant",
        layout="wide",
        initial_sidebar_state="expanded",
        page_icon="🛡️"
    )
    
    # Apply custom CSS styling
    st.markdown(get_css(), unsafe_allow_html=True)


def render_header():
    """Render the main application header."""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Cybersecurity Multi-Framework Assistant</h1>
        <p>Chat with comprehensive cybersecurity frameworks and explore threat intelligence</p>
        <div style="display: flex; gap: 10px; justify-content: center; margin-top: 10px;">
            <span style="background: #1f77b4; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">ATT&CK</span>
            <span style="background: #ff7f0e; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">CIS Controls</span>
            <span style="background: #2ca02c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">NIST CSF</span>
            <span style="background: #d62728; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">HIPAA</span>
            <span style="background: #9467bd; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">FFIEC</span>
            <span style="background: #8c564b; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">PCI DSS</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def initialize_session_state():
    """Initialize Streamlit session state variables."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "knowledge_base_initialized" not in st.session_state:
        st.session_state.knowledge_base_initialized = False


def render_error_troubleshooting():
    """Render troubleshooting information for application errors."""
    st.markdown("""
    ### 🔧 Troubleshooting:
    1. **Neo4j Database**: Ensure Neo4j is running and accessible
    2. **Environment Variables**: Check your `.env` file configuration
    3. **API Key**: Verify your Gemini API key is valid
    4. **Network**: Ensure internet connection for framework data ingestion
    5. **Dependencies**: Run `pip install -r requirements.txt` if needed
    6. **Documents**: Ensure all framework documents are in the `documents/` folder
    7. **Permissions**: Check file system permissions for document access
    """)


def main():
    """
    Main application entry point.
    
    Orchestrates the entire Streamlit application including:
    - Page configuration
    - Database connections
    - Component initialization
    - Tab rendering
    - Multi-framework support
    - Error handling
    """
    # Configure page settings
    configure_page()
    
    # Render header
    render_header()
    
    # Initialize session state
    initialize_session_state()
    
    try:
        # Initialize core application components
        with st.spinner("🔄 Initializing multi-framework application components..."):
            # Create Neo4j database connection
            graph = create_graph_connection()
            
            # Initialize language model
            llm = get_llm()
            
            # Initialize comprehensive cybersecurity knowledge base
            # This now includes ATT&CK, CIS, NIST, HIPAA, FFIEC, and PCI DSS
            initialize_knowledge_base(graph)
        
        # Create main application tabs
        tab1, tab2 = st.tabs(["💬 Multi-Framework Chat", "🔍 Knowledge Base Explorer"])
        
        # Render tab content
        with tab1:
            chat_tab(graph, llm)
        
        with tab2:
            knowledge_base_tab(graph)
        
        # Render sidebar components
        sidebar_components(graph)
        
    except Exception as e:
        # Handle application errors gracefully
        st.error(f"❌ **Application Error:** {str(e)}")
        st.warning("Please check your configuration and try again.")
        render_error_troubleshooting()


if __name__ == "__main__":
    main()