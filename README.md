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
Running the program

```./passession-extractor```
Flags

```-file=myPcapToScan.pcap``` 

```-output=fileToDumpSecretsTo.json```

Note - If the file flag is not utilized, a live capture will be initiated.

