"""
Network Mapper
Maps social network connections and relationships for investigation.
"""

import json
from typing import Dict, List, Set
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkMapper:
    """
    Map and analyze social network connections.
    Identify key players, clusters, and suspicious relationships.
    """

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.clusters = []

    def add_user(self, user_id: str, user_data: Dict) -> None:
        """Add a user node to the network"""
        self.nodes[user_id] = user_data

    def add_connection(self, from_user: str, to_user: str, connection_type: str) -> None:
        """Add a connection between users"""
        self.edges.append({
            'from': from_user,
            'to': to_user,
            'type': connection_type
        })

    def analyze_network(self) -> Dict:
        """Analyze the social network structure"""
        analysis = {
            'total_nodes': len(self.nodes),
            'total_connections': len(self.edges),
            'central_users': self._find_central_users(),
            'isolated_nodes': self._find_isolated_nodes(),
            'connection_density': self._calculate_density(),
        }

        return analysis

    def _find_central_users(self) -> List[Dict]:
        """Find most connected users"""
        connections = defaultdict(int)

        for edge in self.edges:
            connections[edge['from']] += 1
            connections[edge['to']] += 1

        central = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:10]
        return [{'user_id': uid, 'connections': count} for uid, count in central]

    def _find_isolated_nodes(self) -> List[str]:
        """Find users with no connections"""
        connected = set()
        for edge in self.edges:
            connected.add(edge['from'])
            connected.add(edge['to'])

        return [uid for uid in self.nodes.keys() if uid not in connected]

    def _calculate_density(self) -> float:
        """Calculate network density"""
        n = len(self.nodes)
        if n <= 1:
            return 0.0

        max_edges = n * (n - 1)
        return len(self.edges) / max_edges if max_edges > 0 else 0.0

    def identify_clusters(self) -> List[List[str]]:
        """Identify clusters/communities in the network"""
        # Simplified clustering algorithm
        visited = set()
        clusters = []

        for node in self.nodes:
            if node not in visited:
                cluster = self._explore_cluster(node, visited)
                if len(cluster) > 1:
                    clusters.append(cluster)

        self.clusters = clusters
        return clusters

    def _explore_cluster(self, start_node: str, visited: Set[str]) -> List[str]:
        """Explore connected components"""
        cluster = []
        stack = [start_node]

        while stack:
            node = stack.pop()
            if node in visited:
                continue

            visited.add(node)
            cluster.append(node)

            # Find connected nodes
            for edge in self.edges:
                if edge['from'] == node and edge['to'] not in visited:
                    stack.append(edge['to'])
                elif edge['to'] == node and edge['from'] not in visited:
                    stack.append(edge['from'])

        return cluster

    def export_graph(self, output_path: str, format: str = 'json') -> None:
        """Export network graph for visualization"""
        if format == 'json':
            graph_data = {
                'nodes': [{'id': uid, **data} for uid, data in self.nodes.items()],
                'edges': self.edges,
                'statistics': self.analyze_network(),
            }

            with open(output_path, 'w') as f:
                json.dump(graph_data, f, indent=2)

        logger.info(f"Network graph exported to {output_path}")


if __name__ == '__main__':
    mapper = NetworkMapper()
    print("Network Mapper initialized")
