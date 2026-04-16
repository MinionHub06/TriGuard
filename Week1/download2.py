import kagglehub
import shutil
import os

print("Downloading sajid576/sql-injection-dataset...")
path = kagglehub.dataset_download("sajid576/sql-injection-dataset")
print("Downloaded to:", path)

dest_dir = r"c:\Users\omnay\Desktop\lab submissions\Cloud Computing\data"
if not os.path.exists(dest_dir):
    os.makedirs(dest_dir)

for root, dirs, files in os.walk(path):
    for file in files:
        if file.endswith('.csv'):
            shutil.copy(os.path.join(root, file), os.path.join(dest_dir, file))
            print("Copied", file, "to data/")
