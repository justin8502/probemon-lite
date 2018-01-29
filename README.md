# probemon-lite
A graphical modification on probemon. The original can be found here: https://github.com/nikharris0/probemon

This project aims to display the results of nearby 802.11 frames in a neat fashion, similar to airodump-ng. The interface displays the time of the last frame, as well as the MAC address, Vendor, Network, RSSID and # of frames recieved so far. 

This program uses scapy to capture the frames, and uses manuf to match the MAC addresses to manufacturers. 

# Usage
```
usage: probemon-lite.py [-h] [-i INTERFACE] [-t TIME] [-o OUTPUT] [-b MAX_BYTES]
                   [-c MAX_BACKUPS] [-d DELIMITER]

a command line tool for logging 802.11 probe request frames

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        capture interface
  -t TIME, --time TIME  output time format (unix, iso)
  -o OUTPUT, --output OUTPUT
                        logging output location
  -b MAX_BYTES, --max-bytes MAX_BYTES
                        maximum log size in bytes before rotating
  -c MAX_BACKUPS, --max-backups MAX_BACKUPS
                        maximum number of log files to keep
  -d DELIMITER, --delimiter DELIMITER
                        output field delimiter
  ```
