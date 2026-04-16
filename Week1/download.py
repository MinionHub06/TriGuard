import kagglehub
import os

print("Downloading dataset...")
path = kagglehub.dataset_download("syedsaqlainhussain/sql-injection-dataset")
print("Path to dataset files:", path)

print("Files in dataset:")
for root, dirs, files in os.walk(path):
    for file in files:
        print(os.path.relpath(os.path.join(root, file), path))
