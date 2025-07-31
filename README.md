# 🛡️ Cybersecurity ATT&CK Assistant

A Streamlit-based cybersecurity assistant that ingests and analyzes MITRE ATT&CK knowledge base data, providing an intelligent chat interface for threat intelligence exploration.

## 🚀 Features

- **ATT&CK Data Ingestion**: Automatically fetches and processes the latest MITRE ATT&CK framework data
- **Intelligent Chat Interface**: Ask questions about techniques, tactics, threat groups, and malware
- **Knowledge Base Exploration**: Browse techniques by tactics, search by technique IDs, and explore threat group capabilities
- **Neo4j Graph Database**: Stores cybersecurity data in a graph format for complex relationship queries
- **AI-Powered Responses**: Uses Google's Gemini LLM for intelligent responses about cybersecurity topics

## 📋 Prerequisites

- Python 3.8+
- Neo4j Database (local or cloud instance)
- Google Gemini API key
- Internet connection for ATT&CK data fetching

## 🛠️ Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd cybersecurity-attack-assistant
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Copy `.env.example` to `.env` and configure:

   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   MODEL_NAME=gemini-2.5-flash-preview-05-20
   NEO4J_URI=your_neo4j_uri_here
   NEO4J_USERNAME=your_neo4j_username
   NEO4J_PASSWORD=your_neo4j_password
   NEO4J_DATABASE=neo4j
   ```

4. **Run the application**:
   ```bash
   streamlit run app.py
   ```

## 🐳 Docker Deployment

1. **Build the Docker image**:

   ```bash
   docker build -t cybersecurity-attack-app .
   ```

2. **Run the container**:
   ```bash
   docker run -p 8501:8501 --env-file .env cybersecurity-attack-app
   ```

## 💡 Usage

### Chat Interface

- Ask questions about ATT&CK techniques: "Tell me about T1055 Process Injection"
- Inquire about threat groups: "What techniques does APT1 use?"
- Explore tactics: "Show me all techniques for persistence"
- Get malware information: "What is Emotet malware?"

### Knowledge Base Exploration

- **Statistics Dashboard**: View counts of techniques, threat groups, malware, etc.
- **Search by Technique ID**: Look up specific techniques like T1055, T1083
- **Browse by Tactic**: Explore techniques organized by MITRE tactics
- **Threat Group Analysis**: Investigate specific threat actor capabilities

## 🏗️ Architecture

```
├── src/
│   ├── cybersecurity/           # ATT&CK data ingestion
│   │   ├── __init__.py
│   │   └── attack_ingestion.py  # Main ingestion logic
│   ├── knowledge_base/          # Graph database operations
│   │   ├── database.py          # Neo4j connection
│   │   └── graph_operations.py  # Cybersecurity queries
│   ├── api/                     # LLM integration
│   │   └── llm_service.py       # Gemini API wrapper
│   ├── web/                     # UI components
│   │   ├── components.py        # Streamlit components
│   │   └── ui.py               # CSS styles
│   ├── utils/                   # Utilities
│   │   └── initialization.py   # App initialization
│   └── config/                  # Configuration
│       └── settings.py          # Environment settings
├── app.py                       # Main application
├── requirements.txt             # Dependencies
├── Dockerfile                   # Container configuration
└── README.md                    # This file
```

## 🔧 Configuration

### Neo4j Setup

The application requires a Neo4j database instance. You can use:

- Neo4j Desktop (local development)
- Neo4j Aura (cloud service)
- Self-hosted Neo4j instance

### Environment Variables

- `GEMINI_API_KEY`: Your Google Gemini API key
- `NEO4J_URI`: Neo4j connection URI
- `NEO4J_USERNAME`: Database username
- `NEO4J_PASSWORD`: Database password
- `NEO4J_DATABASE`: Database name (usually 'neo4j')

## 🔍 Data Sources

The application ingests data from:

- **MITRE ATT&CK Framework**: Latest techniques, tactics, and procedures
- **Threat Groups**: Known APT groups and their TTPs
- **Malware**: Documented malware families and their behaviors
- **Tools**: Security tools and their capabilities

Data is fetched from the official MITRE CTI repository: https://github.com/mitre/cti

## 🚨 Security Considerations

- Store API keys securely in environment variables
- Use HTTPS in production deployments
- Implement proper authentication for production use
- Regularly update dependencies for security patches
- Consider network security for Neo4j database access

## 🔄 Data Updates

The application fetches the latest ATT&CK data on initialization. To update:

1. Use the "Re-ingest ATT&CK Data" button in the sidebar
2. Or restart the application to fetch fresh data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

[Add your license information here]

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section in the app
2. Verify your environment configuration
3. Ensure Neo4j connectivity
4. Check API key validity

## 🔮 Future Enhancements

- Support for additional cybersecurity frameworks (NIST, ISO 27001)
- Real-time threat intelligence feeds
- Custom threat modeling capabilities
- Integration with SIEM systems
- Advanced visualization of attack paths
- Export capabilities for reports and analysis
