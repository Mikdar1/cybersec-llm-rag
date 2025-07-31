# 🛡️ Cybersecurity Multi-Framework Assistant

A comprehensive Streamlit-based cybersecurity assistant that ingests and analyzes multiple cybersecurity frameworks, providing an intelligent chat interface for multi-framework threat intelligence and compliance exploration.

## 🚀 Features

### 🎯 Multi-Framework Support

- **MITRE ATT&CK**: Threat tactics, techniques, and procedures
- **CIS Controls v8.1**: Critical security controls and safeguards
- **NIST Cybersecurity Framework 2.0**: Core functions and categories
- **HIPAA Administrative Simplification**: Healthcare regulatory compliance
- **FFIEC IT Handbook**: Financial institution examination procedures
- **PCI DSS v4.0.1**: Payment card industry security standards

### 🤖 Intelligence Capabilities

- **Multi-Framework Data Ingestion**: Automatically processes latest framework data
- **Intelligent Chat Interface**: Ask questions across all supported frameworks
- **Cross-Framework Analysis**: Explore relationships between different standards
- **Knowledge Base Exploration**: Browse controls, techniques, and requirements
- **Citation Tracking**: Complete source attribution for all framework elements

### 🏗️ Technical Architecture

- **Neo4j Graph Database**: Complex relationship modeling across frameworks
- **AI-Powered Responses**: Google Gemini LLM for intelligent cybersecurity insights
- **Document Processing**: PDF parsing and structured data extraction
- **Schema Validation**: Consistent data modeling across all frameworks

## 📋 Prerequisites

- Python 3.8+
- Neo4j Database (local or cloud instance)
- Google Gemini API key
- Internet connection for framework data fetching
- Framework documents (PDF files in `documents/` folder)

## 🛠️ Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd cybersecurity-multi-framework-assistant
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

4. **Add framework documents**:
   Place the following PDF documents in the `documents/` folder:

   - `CIS_Controls__v8.1_Guide__2024_06.pdf`
   - `NIST.CSWP.29.pdf`
   - `hipaa-simplification-201303.pdf`
   - `2016- it-handbook-information-security-booklet.pdf`
   - `PCI-DSS-v4_0_1.pdf`

5. **Run the application**:

   ```bash
   streamlit run app.py
   ```

6. **Verify your setup** (optional):
   ```bash
   python verify_setup.py
   ```
   This script checks all dependencies, environment variables, and module imports.

## 🔧 Verification & Troubleshooting

## 🐳 Docker Deployment

1. **Build the Docker image**:

   ```bash
   docker build -t cybersecurity-multi-framework-app .
   ```

2. **Run the container**:
   ```bash
   docker run -p 8501:8501 --env-file .env cybersecurity-multi-framework-app
   ```

## 💡 Usage

### Multi-Framework Chat Interface

- **ATT&CK Questions**: "Tell me about T1055 Process Injection"
- **CIS Controls**: "What are the CIS Controls for network security?"
- **NIST Framework**: "Explain the NIST Cybersecurity Framework Protect function"
- **HIPAA Compliance**: "What are HIPAA requirements for data encryption?"
- **Cross-Framework**: "How do CIS Controls relate to NIST CSF categories?"
- **PCI DSS**: "What are the PCI DSS requirements for cardholder data?"

### Knowledge Base Exploration

- **Multi-Framework Statistics**: View counts across all supported frameworks
- **Framework-Specific Browsing**: Explore controls, techniques, and requirements by framework
- **Cross-Framework Relationships**: Discover connections between different standards
- **Citation Tracking**: Access source documents and references
- **Compliance Mapping**: Map requirements across regulatory frameworks

### Data Analysis Tools

Run the dedicated analyzer for in-depth framework exploration:

```bash
streamlit run data_analyzer.py
```

Features include:

- **Framework Comparison**: Side-by-side analysis of different standards
- **Schema Documentation**: Complete data structure documentation
- **Cross-Framework Mapping**: Relationship analysis between frameworks
- **Export Capabilities**: Generate documentation and reports

## 🏗️ Architecture

```
├── src/
│   ├── cybersecurity/              # Multi-framework data ingestion
│   │   ├── __init__.py
│   │   ├── attack_ingestion.py     # MITRE ATT&CK ingestion
│   │   ├── cis_ingestion.py        # CIS Controls ingestion
│   │   ├── nist_ingestion.py       # NIST CSF ingestion
│   │   ├── hipaa_ingestion.py      # HIPAA regulatory ingestion
│   │   ├── ffiec_ingestion.py      # FFIEC examination procedures
│   │   └── pci_dss_ingestion.py    # PCI DSS security standards
│   ├── knowledge_base/             # Graph database operations
│   │   ├── database.py             # Neo4j connection
│   │   └── graph_operations.py     # Multi-framework queries
│   ├── api/                        # LLM integration
│   │   └── llm_service.py          # Gemini API wrapper
│   ├── web/                        # UI components
│   │   ├── components.py           # Streamlit components
│   │   └── ui.py                  # CSS styles
│   ├── utils/                      # Utilities
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
