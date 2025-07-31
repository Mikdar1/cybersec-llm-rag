# Multi-Framework Cybersecurity Data Analyzer

A comprehensive Streamlit application for analyzing and exploring cybersecurity framework data structures, schemas, and relationships across multiple standards. This tool provides deep insights into framework architectures and supports cross-framework analysis.

## 🎯 Purpose

This analyzer is specifically created for:

- **Multi-Framework Schema Documentation**: Understanding complete data structures across all supported frameworks
- **Cross-Framework Research**: Analyzing relationships and mappings between different standards
- **Data Modeling**: Planning database schemas and multi-framework integrations
- **Compliance Documentation**: Generating comprehensive framework documentation
- **Framework Comparison**: Side-by-side analysis of different cybersecurity standards

## 🚀 Supported Frameworks

### 🔍 MITRE ATT&CK

- **Enterprise, Mobile, ICS datasets**
- Complete object type analysis (techniques, tactics, groups, malware, etc.)
- Relationship mapping and visualization
- Real-time data fetching from MITRE repository

### 🛡️ CIS Controls v8.1

- Critical security controls structure
- Safeguards and implementation groups
- Control-to-technique mappings

### 📋 NIST Cybersecurity Framework 2.0

- Functions, categories, and subcategories hierarchy
- Risk management structure analysis
- Framework implementation guidance

### 🏥 HIPAA Administrative Simplification

- Regulatory compliance requirements
- Healthcare information security standards
- Privacy and security rule analysis

### 🏦 FFIEC IT Examination Handbook

- Financial institution examination procedures
- Information security guidance structure
- Regulatory compliance requirements

### � PCI DSS v4.0.1

- Payment card industry security standards
- Data protection requirements analysis
- Compliance validation procedures

## 🚀 Features

### 📊 Framework Overview

- Complete statistics for all supported frameworks
- Framework type classification and source attribution
- Document availability and status checking
- Framework metadata analysis

### 🎯 Multi-Framework Analysis

- **ATT&CK Deep Dive**: Object types, relationships, schema analysis
- **Framework Structure**: Document parsing and hierarchy analysis
- **Schema Comparison**: Cross-framework data model comparison
- **Citation Tracking**: Source document verification and references

### 🔬 Schema Deep Dive

- Complete property schema for each framework
- Data structure documentation
- Cross-framework relationship mapping
- Implementation guidance analysis

### 🔗 Cross-Framework Relationships

- Framework interoperability analysis
- Compliance mapping opportunities
- Control-to-technique relationships
- Regulatory alignment assessment

### 📄 Export Documentation

- Generate comprehensive framework documentation
- Export analysis data in multiple formats
- Schema documentation for integration planning
- Cross-framework mapping reports

## 🛠️ Installation & Usage

### Prerequisites

```bash
python -m pip install -r analyzer_requirements.txt
```

### Document Setup

Ensure the following framework documents are available in the `documents/` folder:

- `CIS_Controls__v8.1_Guide__2024_06.pdf` - CIS Controls v8.1 Guide
- `NIST.CSWP.29.pdf` - NIST Cybersecurity Framework 2.0
- `hipaa-simplification-201303.pdf` - HIPAA Administrative Simplification
- `2016- it-handbook-information-security-booklet.pdf` - FFIEC IT Handbook
- `PCI-DSS-v4_0_1.pdf` - PCI DSS v4.0.1 Standard

### Running the Analyzer

```bash
streamlit run data_analyzer.py
```

The application will be available at `http://localhost:8501`

### Framework Selection

1. **Select Framework**: Choose from ATT&CK, CIS, NIST, HIPAA, FFIEC, or PCI DSS
2. **Choose Analysis Mode**: Select the type of analysis to perform
3. **ATT&CK Dataset**: For ATT&CK, choose Enterprise, Mobile, or ICS
4. **Refresh Data**: Update framework data when needed

## 📋 Analysis Modes

### 1. Overview Mode

- Quick dataset statistics
- Object type distribution charts
- High-level data insights

### 2. Object Types Mode

- Drill down into specific object types
- View sample objects
- Analyze object collections

### 3. Schema Deep Dive Mode

- Complete property analysis
- Data type identification
- Property frequency statistics
- Schema coverage analysis

### 4. Relationships Mode

- Relationship type analysis
- Source/target mapping
- Relationship pattern visualization

### 5. Export Documentation Mode

- Generate comprehensive documentation
- Export analysis results
- Create integration guides

## 📊 Supported Datasets

- **Enterprise ATT&CK**: Primary enterprise techniques and tactics
- **Mobile ATT&CK**: Mobile-specific attack techniques
- **ICS ATT&CK**: Industrial Control Systems attack techniques

## 🔍 Analysis Capabilities

### Object Type Analysis

- `attack-pattern` (Techniques)
- `malware` (Malware families)
- `intrusion-set` (Threat groups)
- `tool` (Tools and software)
- `course-of-action` (Mitigations)
- `x-mitre-data-source` (Data sources)
- `x-mitre-data-component` (Data components)
- `campaign` (Threat campaigns)
- `relationship` (Object relationships)

### Property Analysis

- Property frequency across objects
- Data type identification
- Value example extraction
- Coverage statistics

### Relationship Mapping

- Source-target relationships
- Relationship type distribution
- Connection pattern analysis

## 📤 Export Formats

### Markdown Documentation

- Complete schema documentation
- Object type summaries
- Property details

### JSON Analysis Data

- Raw analysis results
- Statistical summaries
- Schema information

## 🎯 Use Cases

### For Researchers

- Understanding ATT&CK data structure
- Analyzing technique relationships
- Exploring threat actor patterns

### For Developers

- Planning database schemas
- Understanding API responses
- Designing data integrations

### For Documentation

- Creating schema guides
- Generating data dictionaries
- Producing integration documentation

## 🔧 Technical Details

### Data Sources

- MITRE ATT&CK Enterprise: `enterprise-attack.json`
- MITRE ATT&CK Mobile: `mobile-attack.json`
- MITRE ATT&CK ICS: `ics-attack.json`

### Analysis Features

- Real-time data fetching from MITRE repository
- Interactive visualization with Plotly
- Comprehensive schema analysis
- Export capabilities for documentation

## 📈 Output Examples

### Schema Analysis Output

```
# Object Type: attack-pattern
- Total Objects: 193
- Unique Properties: 25
- Required Properties: id, type, created, modified
- Optional Properties: name, description, kill_chain_phases, ...
```

### Relationship Analysis

```
# Relationship Types
- uses: 1,234 relationships
- mitigates: 456 relationships
- detects: 789 relationships
```

## 🤝 Integration with Main App

This analyzer complements the main cybersecurity assistant by:

- Providing schema insights for better data modeling
- Helping understand the complete ATT&CK structure
- Supporting documentation efforts
- Enabling better integration planning

---

**Note**: This is a standalone analysis tool separate from the main cybersecurity assistant application. It's designed specifically for data exploration and documentation purposes.
