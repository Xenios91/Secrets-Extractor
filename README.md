# Secrets Extractor

[![CodeQL](https://github.com/Xenios91/Secrets-Extractor/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Xenios91/Secrets-Extractor/actions/workflows/codeql-analysis.yml) 
[![Go](https://github.com/Xenios91/Secrets-Extractor/actions/workflows/go.yml/badge.svg)](https://github.com/Xenios91/Secrets-Extractor/actions/workflows/go.yml)

## General Information
- Author: Corey Hartman
- Language: Golang v1.23
- Description: Traverses packet captures/live traffic and extracts: usernames, passwords, session id's, basic auth, and cookies from HTTP traffic.

## Installation/Compilation
- Requires Golang v1.23
- DevContainer included within the project.
- libpcap-dev required ```sudo apt install libpcap-dev -y```
- With in the projects root directory run ```go build .```

## Utilization
- Set the pcap file to check ```-file=myPcapToScan.pcap``` 

- Set the file to output secrets to ```-output=fileToDumpSecretsTo.json```

- Example ```./passession-extractor -file=myPcapCapture.pcap -output=secrets_dump.json```

- Note - If the ```-file``` flag is not utilized, a live capture will be initiated. To utilize live capture, ensure the user you are running as has permissions to perform a packet capture.

