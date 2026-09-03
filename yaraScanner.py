import yara
import os
import csv
from datetime import datetime

rules = yara.compile(filepaths={
	'my_rules' : 'myYaraRules.yar'
})

target_directory = '/home/kali/Desktop'
output_file = 'scan_reults.csv'

results = []

for root, dirs, files in os.walk(target_directory):
	for filename in files:
		filepath = os.path.join(root, filename)
		try:
			matches = rules.match(filepath)
			if matches:
				for match in matches:
					results.append({
						'filename': filepath,
						'rule': match.rule,
						'timestamp': datetime.now().strftime('%Y-%m%d %H:%M:%S')
					})
					print(f"[MATCH] {filepath} -> {match.rule}")
		except yara.Error:
			continue

with open(output_file, 'w', newline='') as csvfile:
	writer = csv.DictWriter(csvfile, fieldnames=['filename', 'rule', 'timestamp'])
	writer.writeheader()
	writer.writerows(results)

print(f"\nDone. {len(results)} match found, written to {output_file}")
