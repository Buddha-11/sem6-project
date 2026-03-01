import csv
import random

random.seed(42)  # reproducibility

vulnerable = []
safe = []

with open("expectedresults-1.2.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0].startswith("#"):
            continue
        test_id = row[0].strip()
        label = row[2].strip().lower()

        if label == "true":
            vulnerable.append(test_id)
        else:
            safe.append(test_id)

sample_vuln = random.sample(vulnerable, 10)
sample_safe = random.sample(safe, 10)

sample = sample_vuln + sample_safe

with open("file_sample.txt", "w") as f:
    for s in sample:
        f.write(s + "\n")

print("Sampled 20 files.")
