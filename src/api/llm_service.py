"""
Large Language Model Integration Service Module

This module provides integration with Google's Gemini LLM for cybersecurity
intelligence analysis and chatbot functionality. It handles LLM initialization,
prompt templating, and context-aware response generation using the MITRE ATT&CK
knowledge base.

Features:
- Google Gemini LLM integration via LangChain
- Cybersecurity-specialized prompt templates
- Context-aware response generation
- ATT&CK knowledge base integration

Functions:
    get_llm: LLM factory and configuration
    chat_with_knowledge_base: Main chat interface with context injection
"""

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import MODEL_NAME, GEMINI_API_KEY


def get_llm():
    """
    Initialize and configure the Google Gemini LLM instance.
    
    Creates a ChatGoogleGenerativeAI instance with cybersecurity-optimized
    settings including temperature control for consistent responses.
    
    Returns:
        ChatGoogleGenerativeAI: Configured LLM instance for chat operations
    """
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        temperature=0,  # Deterministic responses for cybersecurity accuracy
        google_api_key=GEMINI_API_KEY
    )


# Cybersecurity-specialized chat prompt template
chat_template = ChatPromptTemplate.from_template("""
You are a cybersecurity expert assistant with deep knowledge of the MITRE ATT&CK framework. 
You have access to comprehensive cybersecurity intelligence including:

🎯 **ATT&CK Techniques & Tactics**: Complete technique library with T-codes and tactic mappings
🦠 **Malware Intelligence**: Families, variants, and behavioral analysis
👥 **Threat Actor Profiles**: APT groups, their TTPs, and attribution data
🔧 **Tools & Software**: Attack tools, legitimate software abuse, and capabilities
🛡️ **Security Mitigations**: Countermeasures, detection methods, and M-codes
📊 **Data Sources**: Detection data sources and monitoring capabilities
🔗 **Relationships**: Complex mappings between all cybersecurity entities

**Context from ATT&CK Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Provide accurate, detailed responses based on the ATT&CK knowledge base
- Include relevant technique IDs (T####), mitigation codes (M####), and tactic information
- Reference specific threat groups, malware families, or tools when applicable
- If information is not available in the knowledge base, clearly state this limitation
- Suggest related ATT&CK topics or techniques that might be helpful
- Use professional cybersecurity terminology and provide actionable intelligence
""")


def chat_with_knowledge_base(llm, context, user_question):
    """
    Generate context-aware responses using the ATT&CK knowledge base.
    
    Processes user questions with relevant ATT&CK context to provide
    accurate, detailed cybersecurity intelligence responses.
    
    Args:
        llm: Configured language model instance
        context (str): Relevant ATT&CK knowledge base context
        user_question (str): User's cybersecurity question
        
    Returns:
        str: Generated response with cybersecurity intelligence
    """
    try:
        response = llm.invoke(chat_template.format(
            context=context, 
            question=user_question
        ))
        return response.content
    except Exception as e:
        return f"❌ Error generating response: {e}"
