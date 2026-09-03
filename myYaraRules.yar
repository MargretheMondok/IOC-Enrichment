
rule EICAR_Test_File
{
	meta:
		description = "Detekter standard EICAR-antivirus-testfilen"
		author = "Margrethe"
	strings:
		$eicar ="X50!p%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$h+h*"
	condition:
		$eicar
}

rule Suspicious_Encoded_Povershell
{
	meta:
		description = "Flagger filer som inneholder tegn på en base64-kodet Powershell-kommando, en teknikk for å skule en malicious payload"
		author = "Margrethe"
	strings:
		$ps1 = "powershell" nocase
		$enc1 = "-enc" nocase
		$enc2 = "-encodedcommand" nocase
	condition:
		$ps1 and ($enc1 or $enc2)
}


