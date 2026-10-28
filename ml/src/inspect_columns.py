import pandas as pd
from pathlib import Path

f = Path("dataset/TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df = pd.read_csv(f, nrows=10)
print("Columns count:", len(df.columns))
print("Columns list:")
for i, c in enumerate(df.columns):
    print(f" {i}: '{c}' ({df[c].dtype})")

