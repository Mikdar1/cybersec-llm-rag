"""
Neo4j Database Connection and Management Module

This module provides connection management and basic operations for the Neo4j
graph database used to store the MITRE ATT&CK knowledge base. It handles
connection establishment, authentication, query execution, and database
maintenance operations.

Classes:
    Neo4jConnection: Wrapper class for Neo4j database operations

Functions:
    create_graph_connection: Factory function for database connections
    clear_knowledge_base: Database cleanup utility
"""

from neo4j import GraphDatabase
from src.config.settings import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD


class Neo4jConnection:
    """
    Neo4j database connection wrapper with query execution capabilities.
    
    Provides a simplified interface for Neo4j database operations including
    connection management, query execution, and transaction handling.
    
    Attributes:
        driver: Neo4j driver instance for database communication
    """
    
    def __init__(self, uri, username, password):
        """
        Initialize Neo4j connection with authentication.
        
        Args:
            uri (str): Neo4j database URI
            username (str): Database username
            password (str): Database password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
    
    def close(self):
        """Close the database connection and release resources."""
        if self.driver:
            self.driver.close()
    
    def query(self, query, params=None):
        """
        Execute a Cypher query and return results.
        
        Args:
            query (str): Cypher query string
            params (dict, optional): Query parameters
            
        Returns:
            list: Query results as list of dictionaries
        """
        with self.driver.session() as session:
            result = session.run(query, params or {})
            return [record.data() for record in result]


def create_graph_connection():
    """
    Create and return a validated Neo4j graph connection.
    
    Establishes connection to Neo4j database using configuration settings
    and performs connection validation.
    
    Returns:
        Neo4jConnection: Validated database connection instance
        
    Raises:
        ConnectionError: If database connection fails
    """
    try:
        connection = Neo4jConnection(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)
        
        # Validate connection with simple test query
        connection.query("RETURN 1 as test")
        return connection
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Neo4j database: {e}")


def clear_knowledge_base(graph):
    """
    Clear all data from the knowledge base.
    
    Removes all nodes and relationships from the Neo4j database.
    Use with caution as this operation is irreversible.
    
    Args:
        graph (Neo4jConnection): Database connection instance
        
    Returns:
        bool: True if operation successful
        
    Raises:
        Exception: If database cleanup fails
    """
    try:
        graph.query("MATCH (n) DETACH DELETE n")
        return True
    except Exception as e:
        raise Exception(f"Could not clear existing data: {e}")
