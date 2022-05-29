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
- Running the program

- Set pcap file to check ```-file=myPcapToScan.pcap``` 

- Set file to output secrets to ```-output=fileToDumpSecretsTo.json```

- Example ```./passession-extractor -file=myPcapCapture.pcap -output=secrets_dump.json```

- Note - If the file flag is not utilized, a live capture will be initiated.

