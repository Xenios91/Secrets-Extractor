# passession-extractor

## General Information
- Author: Corey Hartman
- Language: Golang v1.18
- Description: Traverses packet captures and extracts: usernames, passwords, session ids, basic auth, and cookies.

## Video URL

## Installation/Compilation
- Requires Golang v1.18
- DevContainer included within the project.
- With in the projects root directory run ```go build .```

## Utilization
```-file=myPcapToScan.pcap``` If file is not utilized, a live capture will initiate.

```-output=fileToDumpSecretsTo.json```

