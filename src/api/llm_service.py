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
- Document parsing and extraction services

Functions:
    get_llm: LLM factory and configuration
    chat_with_knowledge_base: Main chat interface with context injection
    
Classes:
    LLMService: Main service class for document extraction and analysis
"""

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import MODEL_NAME, GEMINI_API_KEY
import logging


class LLMService:
    """
    Service class for LLM-based document parsing and analysis.
    
    Provides methods for extracting structured data from cybersecurity
    framework documents using Google Gemini LLM.
    """
    
    def __init__(self):
        """Initialize the LLM service."""
        self.llm = self._get_llm()
    
    def _get_llm(self):
        """Initialize and configure the Google Gemini LLM instance."""
        return ChatGoogleGenerativeAI(
            model=MODEL_NAME,
            temperature=0.1,  # Low temperature for consistent extraction
            google_api_key=GEMINI_API_KEY
        )
    
    def generate_response(self, prompt: str) -> str:
        """
        Generate a response from the LLM based on the given prompt.
        
        Args:
            prompt (str): The input prompt for the LLM
            
        Returns:
            str: The LLM's response
        """
        try:
            response = self.llm.invoke(prompt)
            if hasattr(response, 'content'):
                content = response.content
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    return str(content)
                else:
                    return str(content)
            else:
                return str(response)
        except Exception as e:
            logging.error(f"LLM generation failed: {e}")
            raise


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


# Query analysis prompt template for determining relevant ATT&CK object types
query_analysis_template = ChatPromptTemplate.from_template("""
You are a cybersecurity query analyzer. Your task is to analyze user questions and determine which MITRE ATT&CK object types are most relevant to answer the question effectively.

**Available ATT&CK Object Types:**
- techniques: ATT&CK techniques (T-codes), tactics, and procedures
- malware: Malware families, variants, and malicious software
- threat_groups: APT groups, threat actors, and cybercriminal organizations
- tools: Attack tools, legitimate software abuse, and utilities
- mitigations: Security countermeasures, detection methods (M-codes)
- data_sources: Detection data sources and monitoring capabilities
- campaigns: Threat campaigns and coordinated attacks

**User Question:** {question}

**Instructions:**
Analyze the question and return ONLY a JSON object with the following structure:
{{
    "relevant_types": ["type1", "type2", ...],
    "keywords": ["keyword1", "keyword2", ...],
    "focus": "primary_focus_description"
}}

**Rules:**
- Include only the most relevant object types (typically 2-4 types)
- Extract 3-5 key terms that should be used for searching
- Focus should be a brief description of what the user wants to know
- Be selective - don't include all types unless the question is very broad

**Examples:**
Question: "Tell me about APT28 techniques"
Response: {{"relevant_types": ["threat_groups", "techniques"], "keywords": ["APT28", "Fancy Bear"], "focus": "specific threat group techniques"}}

Question: "How to detect process injection?"
Response: {{"relevant_types": ["techniques", "data_sources", "mitigations"], "keywords": ["process injection", "T1055"], "focus": "detection and mitigation methods"}}

Question: "What is Emotet malware?"
Response: {{"relevant_types": ["malware", "techniques"], "keywords": ["Emotet", "banking trojan"], "focus": "malware analysis and capabilities"}}
""")


def analyze_user_query(llm, user_question):
    """
    Analyze user question to determine relevant ATT&CK object types and keywords.
    
    Uses LLM to intelligently parse the user's question and identify which
    specific ATT&CK object types should be queried for optimal context retrieval.
    
    Args:
        llm: Configured language model instance
        user_question (str): User's cybersecurity question
        
    Returns:
        dict: Analysis results with relevant_types, keywords, and focus
    """
    try:
        response = llm.invoke(query_analysis_template.format(question=user_question))
        
        # Parse the JSON response
        import json
        analysis = json.loads(response.content.strip())
        
        # Validate the response structure
        if not isinstance(analysis.get('relevant_types'), list):
            analysis['relevant_types'] = ['techniques', 'malware', 'threat_groups']
        if not isinstance(analysis.get('keywords'), list):
            analysis['keywords'] = [user_question]
        if not analysis.get('focus'):
            analysis['focus'] = "general cybersecurity inquiry"
            
        return analysis
        
    except Exception as e:
        # Fallback to basic analysis if LLM fails
        return {
            'relevant_types': ['techniques', 'malware', 'threat_groups'],
            'keywords': [user_question],
            'focus': 'general cybersecurity inquiry'
        }


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
