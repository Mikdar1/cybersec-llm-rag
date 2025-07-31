# ATT&CK Data Schema Analyzer

A specialized Streamlit application for analyzing and exploring the raw MITRE ATT&CK data structure, schema, and relationships. This tool is designed to help with documentation, data modeling, and understanding the complete ATT&CK framework structure.

## 🎯 Purpose

This analyzer is specifically created for:

- **Schema Documentation**: Understanding the complete data structure
- **Research & Analysis**: Deep diving into ATT&CK object relationships
- **Data Modeling**: Planning database schemas and integrations
- **Documentation**: Generating comprehensive schema documentation

## 🚀 Features

### 📊 Dataset Overview

- Complete statistics for Enterprise, Mobile, and ICS ATT&CK datasets
- Object type distribution visualization
- Basic dataset metadata analysis

### 🎯 Object Type Analysis

- Detailed analysis of each ATT&CK object type
- Sample object examination
- Object listing and filtering

### 🔬 Schema Deep Dive

- Complete property schema for each object type
- Property frequency analysis
- Data type identification
- Property coverage statistics

### 🔗 Relationship Analysis

- Relationship type distribution
- Source/target object mapping
- Relationship pattern analysis

### 📄 Export Documentation

- Generate Markdown documentation
- Export analysis data as JSON
- Schema documentation for integration planning

## 🛠️ Installation & Usage

### Prerequisites

```bash
python -m pip install -r analyzer_requirements.txt
```

### Running the Analyzer

```bash
streamlit run attack_data_analyzer.py
```

The application will be available at `http://localhost:8501`

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
