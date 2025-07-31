#!/usr/bin/env python3
"""
Cybersecurity Knowledge Base Setup Verification Script

This script verifies that all dependencies, configurations, and modules
are properly set up for the cybersecurity multi-framework knowledge base.

Usage:
    python verify_setup.py
"""

import sys
import os
import importlib
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    print("🔍 Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True


def check_dependencies():
    """Check if all required dependencies are installed."""
    print("\n🔍 Checking dependencies...")
    
    required_packages = [
        'streamlit',
        'neo4j',
        'python-dotenv',
        'langchain_google_genai',
        'langchain_core',
        'PyPDF2',
        'pandas',
        'requests',
        'plotly',
        'watchdog'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'python-dotenv':
                importlib.import_module('dotenv')
            elif package == 'langchain_google_genai':
                importlib.import_module('langchain_google_genai')
            elif package == 'langchain_core':
                importlib.import_module('langchain_core')
            elif package == 'PyPDF2':
                importlib.import_module('PyPDF2')
            else:
                importlib.import_module(package.lower())
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
        print("💡 Run: pip install -r requirements.txt")
        return False
    
    return True


def check_environment_files():
    """Check if required environment files exist."""
    print("\n🔍 Checking environment configuration...")
    
    env_file = Path('.env')
    if not env_file.exists():
        print("❌ .env file not found")
        print("💡 Copy .env.example to .env and configure your settings")
        return False
    
    print("✅ .env file exists")
    
    # Check for required environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = [
        'NEO4J_URI',
        'NEO4J_USERNAME',
        'NEO4J_PASSWORD',
        'GEMINI_API_KEY'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
            print(f"❌ {var} not set")
        else:
            print(f"✅ {var} configured")
    
    if missing_vars:
        print(f"\n❌ Missing environment variables: {', '.join(missing_vars)}")
        return False
    
    return True


def check_src_modules():
    """Check if all source modules can be imported."""
    print("\n🔍 Checking source modules...")
    
    # Add src to path for testing
    src_path = Path('src').absolute()
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    modules_to_check = [
        'src.config.settings',
        'src.api.llm_service',
        'src.knowledge_base.database',
        'src.knowledge_base.graph_operations',
        'src.cybersecurity.attack_ingestion',
        'src.cybersecurity.cis_ingestion',
        'src.cybersecurity.nist_ingestion',
        'src.cybersecurity.hipaa_ingestion',
        'src.cybersecurity.ffiec_ingestion',
        'src.cybersecurity.pci_dss_ingestion',
        'src.web.components',
        'src.web.ui',
        'src.utils.initialization'
    ]
    
    failed_modules = []
    
    for module in modules_to_check:
        try:
            importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")
            failed_modules.append(module)
    
    if failed_modules:
        print(f"\n❌ Failed to import: {', '.join(failed_modules)}")
        return False
    
    return True


def check_document_directory():
    """Check if document directory exists and has PDF files."""
    print("\n🔍 Checking document directory...")
    
    doc_dir = Path('documents')
    if not doc_dir.exists():
        print("❌ documents/ directory not found")
        print("💡 Create documents/ directory and add framework PDF files")
        return False
    
    pdf_files = list(doc_dir.glob('*.pdf'))
    if not pdf_files:
        print("⚠️  No PDF files found in documents/ directory")
        print("💡 Add cybersecurity framework PDF files to documents/ directory")
        return False
    
    print(f"✅ documents/ directory exists with {len(pdf_files)} PDF files")
    for pdf in pdf_files:
        print(f"   📄 {pdf.name}")
    
    return True


def check_neo4j_connection():
    """Check if Neo4j connection can be established."""
    print("\n🔍 Checking Neo4j connection...")
    
    try:
        from src.knowledge_base.database import create_graph_connection
        
        # Test connection
        graph = create_graph_connection()
        if graph:
            print("✅ Neo4j connection successful")
            return True
        else:
            print("❌ Could not establish Neo4j connection")
            return False
    except Exception as e:
        print(f"❌ Neo4j connection error: {e}")
        print("💡 Check your Neo4j configuration in .env file")
        return False


def main():
    """Run all verification checks."""
    print("🛡️ Cybersecurity Knowledge Base Setup Verification\n")
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Environment Files", check_environment_files),
        ("Source Modules", check_src_modules),
        ("Document Directory", check_document_directory),
        ("Neo4j Connection", check_neo4j_connection)
    ]
    
    passed_checks = 0
    total_checks = len(checks)
    
    for check_name, check_func in checks:
        try:
            if check_func():
                passed_checks += 1
        except Exception as e:
            print(f"❌ {check_name}: Unexpected error - {e}")
    
    print(f"\n📊 Verification Results: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print("🎉 All checks passed! Your setup is ready.")
        print("\n🚀 You can now run:")
        print("   streamlit run app.py")
        return True
    else:
        print("❌ Some checks failed. Please address the issues above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
