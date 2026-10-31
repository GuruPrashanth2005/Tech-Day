import pandas as pd
import numpy as np
import json
import os

RAW_CSV_PATH = os.path.join("data", "financial_fraud_detection_dataset.csv")
OUTPUT_SUBGRAPH_PATH = os.path.join("backend", "subgraph_sample.json")
OUTPUT_CSV_SAMPLE = os.path.join("backend", "subgraph_sample.csv")

def extract_dense_subgraph(sample_size=10000):
    print("Reading dataset headers and high-risk chunks...")
    
    # We read in chunks to find fraud transactions with high velocity and shared devices
    chunk_size = 50000
    fraud_dfs = []
    normal_dfs = []
    
    total_fraud_needed = 2500
    total_normal_needed = 7500
    
    for chunk in pd.read_csv(RAW_CSV_PATH, chunksize=chunk_size):
        frauds = chunk[chunk['is_fraud'] == True]
        normals = chunk[chunk['is_fraud'] == False]
        
        if len(frauds) > 0 and len(fraud_dfs) * chunk_size < total_fraud_needed * 5:
            fraud_dfs.append(frauds)
            
        if len(normals) > 0 and len(normal_dfs) * chunk_size < total_normal_needed * 5:
            normal_dfs.append(normals.sample(min(len(normals), 1500), random_state=42))
            
        current_fraud_count = sum(len(f) for f in fraud_dfs)
        current_normal_count = sum(len(n) for n in normal_dfs)
        
        if current_fraud_count >= total_fraud_needed and current_normal_count >= total_normal_needed:
            break

    print("Concatenating sampled data...")
    df_fraud = pd.concat(fraud_dfs, ignore_index=True).head(total_fraud_needed)
    df_normal = pd.concat(normal_dfs, ignore_index=True).head(total_normal_needed)
    
    combined_df = pd.concat([df_fraud, df_normal], ignore_index=True).sample(frac=1.0, random_state=42)
    
    # Fill missing values
    combined_df['fraud_type'] = combined_df['fraud_type'].fillna('none')
    combined_df['time_since_last_transaction'] = combined_df['time_since_last_transaction'].fillna(combined_df['time_since_last_transaction'].median())
    
    # Ensure numeric columns are clean
    num_cols = ['amount', 'spending_deviation_score', 'velocity_score', 'geo_anomaly_score']
    for col in num_cols:
        combined_df[col] = pd.to_numeric(combined_df[col], errors='coerce').fillna(0)
        
    print(f"Sample created: {len(combined_df)} records ({len(df_fraud)} frauds, {len(df_normal)} normal)")
    
    # Save CSV sample for fast model training
    combined_df.to_csv(OUTPUT_CSV_SAMPLE, index=False)
    print(f"Saved clean sample CSV to {OUTPUT_CSV_SAMPLE}")
    return combined_df

if __name__ == "__main__":
    extract_dense_subgraph()

