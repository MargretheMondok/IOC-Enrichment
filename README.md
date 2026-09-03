
# YARA-based file scanner

Python script that searches through the filesystem up against Yara-rules to detect know and custom/user-defined malware patterns.

## What it does
- Compile Yara-rules from one ore multiple .yar-files
- Searches through a target folder 
- Reports matches tp the consol and a CVS-file

## Own rules
'myYaraRules' contains two self written tules:
- 'EICAR_Test_file': which recognizes the standard EICAR-antivirus test string,used to validate that the detection works
- 'Suspicious_Encoded_Poweshell': falgs files that combine the word "powershell" with a flagged code word for coded commands (-enc/-encodedcommand), a common technique to hide malicious payloads

## Example of a Match
python3 yaraScanner.py
[MATCH] /home/kali/Desktop/NetworkCapture.etl -> Suspicious_Encoded_Povershell

Done. 1 match found, written to scan_reults.csv

## Further use
the script might be pointed at larger, more established rule sets like [Yara-Rules] (https://github.com/Yara-Rules/rules) for broader coverage, by adding more file paths to 'yara.compile()'.



