import pandas as pd

def load_logs(file_path):
    print(f"[+] Loading logs from {file_path}")
    return pd.read_csv(file_path).to_dict(orient='records')