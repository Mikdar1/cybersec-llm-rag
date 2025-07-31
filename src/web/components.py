"""
Streamlit components for the cybersecurity ATT&CK application.
"""
import streamlit as st

from src.knowledge_base.graph_operations import (
    get_context_from_knowledge_base, get_attack_statistics, get_techniques_by_tactic,
    get_threat_group_techniques, search_by_technique_id, get_all_tactics, get_all_threat_groups
)
from src.api.llm_service import chat_with_knowledge_base
from src.utils.initialization import reingest_attack_data

def chat_tab(graph, llm):
    """Display the chat tab for interacting with the cybersecurity AI assistant."""
    st.markdown("### 💬 Ask Your Cybersecurity AI Assistant")
    
    # Display chat messages only if there are any
    if st.session_state.messages:
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for message in st.session_state.messages:
            if message["role"] == "user":
                st.markdown(f'<div class="user-message">👤 {message["content"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="assistant-message">🤖 {message["content"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("💡 Start a conversation by asking about ATT&CK techniques, threat groups, malware, or cybersecurity tactics. For example: 'Tell me about T1055 Process Injection' or 'What techniques does APT1 use?'")
    
    # Chat input
    user_input = st.chat_input("Ask me anything about cybersecurity and ATT&CK...")
    
    if user_input:
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        # Get AI response
        with st.spinner("Analyzing cybersecurity data..."):
            # Get context from the knowledge base
            context = get_context_from_knowledge_base(graph, user_input)
            
            # Generate response using LLM
            response = chat_with_knowledge_base(llm, context, user_input)
        
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})
        
        # Rerun to update the chat display
        st.rerun()

def knowledge_base_tab(graph):
    """Display the knowledge base exploration tab."""
    st.markdown("""
    <div class="kb-section">
        <h2 style="color: inherit;">� Explore ATT&CK Knowledge Base</h2>
        <p style="color: inherit;">Browse and explore the MITRE ATT&CK knowledge base</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Statistics section
    with st.expander("📊 Knowledge Base Statistics", expanded=True):
        try:
            stats = get_attack_statistics(graph)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Techniques", stats.get('techniques', 0))
                st.metric("Malware", stats.get('malware', 0))
            
            with col2:
                st.metric("Threat Groups", stats.get('threat_groups', 0))
                st.metric("Tools", stats.get('tools', 0))
            
            with col3:
                st.metric("Tactics", stats.get('tactics', 0))
                st.metric("Relationships", stats.get('relationships', 0))
                
        except Exception as e:
            st.error(f"Error loading statistics: {e}")
    
    # Search section
    st.markdown("### 🔎 Search Knowledge Base")
    
    search_type = st.radio(
        "Search by:",
        ["Technique ID", "Tactic", "Threat Group"],
        horizontal=True
    )
    
    if search_type == "Technique ID":
        technique_id = st.text_input("Enter Technique ID (e.g., T1055):")
        if technique_id and st.button("Search Technique"):
            try:
                result = search_by_technique_id(graph, technique_id.upper())
                if result:
                    st.markdown(f"### {result['technique_id']} - {result['name']}")
                    st.markdown(f"**Description:** {result['description']}")
                    
                    if result['platforms']:
                        st.markdown(f"**Platforms:** {', '.join(result['platforms'])}")
                    
                    if result['tactics']:
                        st.markdown(f"**Tactics:** {', '.join(result['tactics'])}")
                    
                    if result['threat_groups']:
                        threat_groups = [group for group in result['threat_groups'] if group]
                        if threat_groups:
                            st.markdown(f"**Used by Threat Groups:** {', '.join(threat_groups)}")
                    
                    if result['malware']:
                        malware_list = [malware for malware in result['malware'] if malware]
                        if malware_list:
                            st.markdown(f"**Associated Malware:** {', '.join(malware_list)}")
                else:
                    st.warning(f"Technique {technique_id} not found.")
            except Exception as e:
                st.error(f"Error searching technique: {e}")
    
    elif search_type == "Tactic":
        try:
            tactics = get_all_tactics(graph)
            if tactics:
                selected_tactic = st.selectbox("Select a tactic:", tactics)
                if selected_tactic and st.button("Show Techniques"):
                    techniques = get_techniques_by_tactic(graph, selected_tactic)
                    if techniques:
                        st.markdown(f"### Techniques for {selected_tactic.title()} Tactic")
                        for tech in techniques:
                            with st.expander(f"{tech['technique_id']} - {tech['name']}"):
                                st.markdown(tech['description'][:500] + "...")
                    else:
                        st.info("No techniques found for this tactic.")
            else:
                st.info("No tactics found in the knowledge base.")
        except Exception as e:
            st.error(f"Error loading tactics: {e}")
    
    elif search_type == "Threat Group":
        try:
            threat_groups = get_all_threat_groups(graph)
            if threat_groups:
                group_names = [group['name'] for group in threat_groups if group['name']]
                selected_group = st.selectbox("Select a threat group:", group_names)
                if selected_group and st.button("Show Techniques"):
                    techniques = get_threat_group_techniques(graph, selected_group)
                    if techniques:
                        st.markdown(f"### Techniques used by {selected_group}")
                        for tech in techniques:
                            with st.expander(f"{tech['technique_id']} - {tech['technique_name']}"):
                                st.markdown(f"**Relationship:** {tech['relationship_type']}")
                                st.markdown(tech['description'][:500] + "...")
                    else:
                        st.info("No techniques found for this threat group.")
            else:
                st.info("No threat groups found in the knowledge base.")
        except Exception as e:
            st.error(f"Error loading threat groups: {e}")

def sidebar_components(graph):
    """Display the sidebar components."""
    st.sidebar.markdown("### 🛡️ Cybersecurity KB")
    st.sidebar.markdown("**Features:**")
    st.sidebar.markdown("• Chat with ATT&CK knowledge base")
    st.sidebar.markdown("• Explore techniques and tactics")
    st.sidebar.markdown("• Search threat intelligence")
    st.sidebar.markdown("• Browse threat groups and malware")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### � Knowledge Base Info")
    
    try:
        stats = get_attack_statistics(graph)
        st.sidebar.markdown(f"**Techniques:** {stats.get('techniques', 0)}")
        st.sidebar.markdown(f"**Threat Groups:** {stats.get('threat_groups', 0)}")
        st.sidebar.markdown(f"**Malware:** {stats.get('malware', 0)}")
        st.sidebar.markdown(f"**Tools:** {stats.get('tools', 0)}")
    except:
        st.sidebar.error("Could not load statistics.")

    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Re-ingest ATT&CK Data"):
        if st.session_state.knowledge_base_initialized:
            if st.sidebar.button("⚠️ Confirm Re-ingest", key="confirm_reingest"):
                st.warning("Re-ingesting ATT&CK data may take some time. Please do not close the browser.")
                
                success = reingest_attack_data(graph)
                if success:
                    st.sidebar.success("🎉 Successfully re-ingested ATT&CK data!")
                    st.rerun()
                else:
                    st.sidebar.error("❌ Failed to re-ingest data.")
        else:
            st.sidebar.info("Knowledge base is not initialized.")

    if st.sidebar.button("🔄 Reset Knowledge Base"):
        try:
            from src.knowledge_base.database import clear_knowledge_base
            clear_knowledge_base(graph)
            st.session_state.knowledge_base_initialized = False
            st.session_state.messages = []
            st.success("Knowledge base reset successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Error resetting knowledge base: {e}")

    if st.sidebar.button("💬 Clear Chat History"):
        st.session_state.messages = []
        st.rerun()
