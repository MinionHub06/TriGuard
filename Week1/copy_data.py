import shutil
import os

src_path = r"C:\Users\omnay\.cache\kagglehub\datasets\syedsaqlainhussain\sql-injection-dataset\versions\5"
dest_path = r"c:\Users\omnay\Desktop\lab submissions\Cloud Computing\data"

if not os.path.exists(dest_path):
    os.makedirs(dest_path)

for file in os.listdir(src_path):
    if file.endswith('.csv'):
        shutil.copy(os.path.join(src_path, file), os.path.join(dest_path, file))
        print("Copied", file, "to data/")
