"""
Cybersecurity ATT&CK Assistant

A Streamlit application that provides an interactive interface for exploring
and chatting with the MITRE ATT&CK knowledge base stored in Neo4j.

Features:
- Interactive chat with ATT&CK knowledge base
- Comprehensive ATT&CK data exploration
- Graph-based cybersecurity intelligence
- Real-time data ingestion from MITRE repository

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
        page_title="Cybersecurity ATT&CK Assistant",
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
        <h1>🛡️ Cybersecurity ATT&CK Assistant</h1>
        <p>Chat with MITRE ATT&CK knowledge base and explore threat intelligence</p>
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
    4. **Network**: Ensure internet connection for ATT&CK data ingestion
    5. **Dependencies**: Run `pip install -r requirements.txt` if needed
    """)


def main():
    """
    Main application entry point.
    
    Orchestrates the entire Streamlit application including:
    - Page configuration
    - Database connections
    - Component initialization
    - Tab rendering
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
        with st.spinner("🔄 Initializing application components..."):
            # Create Neo4j database connection
            graph = create_graph_connection()
            
            # Initialize language model
            llm = get_llm()
            
            # Initialize ATT&CK knowledge base
            initialize_knowledge_base(graph)
        
        # Create main application tabs
        tab1, tab2 = st.tabs(["💬 Chat Assistant", "🔍 Knowledge Base Explorer"])
        
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