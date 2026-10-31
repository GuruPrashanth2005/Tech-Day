import pandas as pd
import numpy as np
import networkx as nx
from sklearn.ensemble import IsolationForest
import json
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_SAMPLE_PATH = os.path.join(BASE_DIR, "subgraph_sample.csv")

class GraphMLEngine:
    def __init__(self, data_path=CSV_SAMPLE_PATH):
        self.df = pd.read_csv(data_path)
        self.G = nx.DiGraph()
        self.iso_forest = None
        self.node_embeddings = {}
        self.build_graph()
        self.train_isolation_forest()
        self.compute_node2vec_embeddings()

    def build_graph(self):
        """Builds heterogeneous graph with Accounts, Devices, and IP addresses."""
        print("Constructing NetworkX Graph...")
        for _, row in self.df.iterrows():
            sender = str(row['sender_account'])
            receiver = str(row['receiver_account'])
            device = str(row['device_hash'])
            ip = str(row['ip_address'])
            amount = float(row['amount'])
            txn_id = str(row['transaction_id'])
            timestamp = str(row['timestamp'])
            is_fraud = bool(row['is_fraud'])
            
            # Add Account nodes
            self.G.add_node(sender, type='account', role='sender', is_fraud=is_fraud)
            self.G.add_node(receiver, type='account', role='receiver', is_fraud=is_fraud)
            
            # Add Device and IP nodes
            self.G.add_node(device, type='device', is_fraud=is_fraud)
            self.G.add_node(ip, type='ip', is_fraud=is_fraud)
            
            # Add edges
            # 1. Money transfer edge
            self.G.add_edge(sender, receiver, 
                            type='TRANSACTION', 
                            txn_id=txn_id, 
                            amount=amount, 
                            timestamp=timestamp, 
                            is_fraud=is_fraud)
            
            # 2. Digital footprint edges
            self.G.add_edge(sender, device, type='USED_DEVICE')
            self.G.add_edge(sender, ip, type='USED_IP')
            
        print(f"Graph constructed: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges")

    def train_isolation_forest(self):
        """Trains Isolation Forest on behavioral deviation & velocity features."""
        print("Training Isolation Forest Anomaly Detector...")
        feature_cols = ['amount', 'spending_deviation_score', 'velocity_score', 'geo_anomaly_score']
        X = self.df[feature_cols].fillna(0)
        
        self.iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.iso_forest.fit(X)
        
        # Decision function gives raw score (lower = more anomalous)
        raw_scores = self.iso_forest.decision_function(X)
        # Normalize into 0 - 100 risk score
        min_score, max_score = raw_scores.min(), raw_scores.max()
        normalized_scores = 100 * (1 - (raw_scores - min_score) / (max_score - min_score + 1e-9))
        self.df['anomaly_score'] = normalized_scores
        print("Isolation Forest trained successfully.")

    def compute_node2vec_embeddings(self, dimensions=16, walk_length=6, num_walks=3):
        """
        Lightweight custom Random Walk Node Embeddings (Node2Vec style)
        Optimized for instant indexing during uploads.
        """
        print("Generating Node2Vec Structural Graph Embeddings...")
        nodes = list(self.G.nodes())
        target_nodes = nodes if len(nodes) < 2000 else random.sample(nodes, 2000)
        walks = []
        
        # Perform fast random walks
        for node in target_nodes:
            for _ in range(num_walks):
                walk = [node]
                curr = node
                for _ in range(walk_length - 1):
                    neighbors = list(self.G.neighbors(curr))
                    if not neighbors:
                        break
                    curr = random.choice(neighbors)
                    walk.append(curr)
                walks.append(walk)
                
        # Generate hash-based dense feature representations for nodes based on co-occurrence in walks
        co_occurrence = {n: {} for n in target_nodes}
        for walk in walks:
            for i, n1 in enumerate(walk):
                for j in range(max(0, i-2), min(len(walk), i+3)):
                    if i != j and n1 in co_occurrence:
                        n2 = walk[j]
                        co_occurrence[n1][n2] = co_occurrence[n1].get(n2, 0) + 1
                        
        # Project into dense vectors
        random.seed(42)
        for n in target_nodes:
            vec = np.zeros(dimensions)
            for neighbor, count in co_occurrence[n].items():
                hash_val = hash(neighbor) % dimensions
                vec[hash_val] += count
            norm = np.linalg.norm(vec)
            self.node_embeddings[n] = (vec / (norm + 1e-9)).tolist()
            
        print(f"Generated structural embeddings for {len(self.node_embeddings)} nodes.")

    def get_ego_network(self, account_id, hops=2):
        """
        Extracts rich syndicate subgraph:
        Traverses Target -> Shared Devices/IPs -> Colliding Accounts -> Transactions.
        """
        if account_id not in self.G:
            fraud_accounts = [n for n, d in self.G.nodes(data=True) if d.get('type') == 'account' and d.get('is_fraud') == True]
            account_id = fraud_accounts[0] if fraud_accounts else list(self.G.nodes())[0]

        sub_nodes = set([account_id])
        
        # 1. First hop: Direct neighbors (Devices used, IPs used, Direct counterparties)
        direct_neighbors = set(self.G.successors(account_id)).union(self.G.predecessors(account_id))
        sub_nodes.update(direct_neighbors)
        
        # 2. Second hop: For each device or IP, pull ALL other accounts that shared it (Mule Ring Collisions!)
        for neighbor in direct_neighbors:
            attr = self.G.nodes.get(neighbor, {})
            if attr.get('type') in ['device', 'ip']:
                colliding_accounts = set(self.G.predecessors(neighbor)).union(self.G.successors(neighbor))
                # Add up to 5 colliding accounts for rich network
                sub_nodes.update(list(colliding_accounts)[:5])
            elif attr.get('type') == 'account':
                # Add counterparties of counterparties
                second_hop_txns = set(self.G.successors(neighbor)).union(self.G.predecessors(neighbor))
                sub_nodes.update(list(second_hop_txns)[:3])
                
        # Limit to reasonable dense view (around 10-18 nodes max so it stays clean)
        if len(sub_nodes) > 20:
            sub_nodes = set(list(sub_nodes)[:20])
            
        subG = self.G.subgraph(sub_nodes)
        
        nodes_data = []
        for n, attr in subG.nodes(data=True):
            node_type = attr.get('type', 'account')
            is_fraud = attr.get('is_fraud', False)
            degree = subG.degree(n)
            
            nodes_data.append({
                "id": str(n),
                "label": str(n),
                "type": node_type,
                "is_fraud": is_fraud,
                "degree": degree,
                "embedding": self.node_embeddings.get(n, [])[:4]
            })
            
        edges_data = []
        for u, v, attr in subG.edges(data=True):
            edges_data.append({
                "source": str(u),
                "target": str(v),
                "type": attr.get('type', 'TRANSACTION'),
                "amount": attr.get('amount', 0),
                "txn_id": attr.get('txn_id', ''),
                "timestamp": attr.get('timestamp', '')
            })
            
        ego_txns = self.df[(self.df['sender_account'] == account_id) | (self.df['receiver_account'] == account_id)]
        anomaly_score = float(ego_txns['anomaly_score'].max()) if not ego_txns.empty else 75.0
        
        return {
            "target_account": account_id,
            "nodes": nodes_data,
            "edges": edges_data,
            "stats": {
                "total_nodes": len(nodes_data),
                "total_edges": len(edges_data),
                "anomaly_score": round(anomaly_score, 1),
                "shared_devices": sum(1 for n in nodes_data if n['type'] == 'device'),
                "shared_ips": sum(1 for n in nodes_data if n['type'] == 'ip')
            }
        }

if __name__ == "__main__":
    engine = GraphMLEngine()
    sample_ego = engine.get_ego_network("test_account")
    print(f"Sample Ego Network extracted: {sample_ego['stats']}")

