<p align="center"><img width=400 alt="NekoDNS" src="https://github.com/JoelGMSec/NekoDNS/blob/main/NekoDNS.png"></p>

# NekoDNS

### Experimental Reverse DNS Shell

NekoDNS is an experimental Reverse DNS Shell that leverages **DNS resolutions** to establish a covert shell over UDP or TCP.  
Communication is performed through DNS queries (AAAA/A records) that carry commands and responses as fragmented and reversed hexadecimal data, making detection by automated tools very difficult. The project provides a **server (Python)** and clients in **Bash (Linux)** and **PowerShell (Windows)** to support different environments.


## ✨ Features

- 🔍 **Evasion**: Random data and domains in each request (`-random`)
- ⚡ **Flow control**: Adjustable chunk size and sleep interval (`-l`, `-i`)
- 📂 **File management**: Built-in **upload/download** support
- 💻 **Cross-platform**: Linux (Bash) and Windows (PowerShell) clients
- 🐱 **Integration**: Fully integrated into Kitsune (https://github.com/JoelGMSec/Kitsune)
- 🔑 **Privilege escalation support** with `sudo`/`su` in Linux
- 📜 **Import PowerShell scripts** directly on Windows clients (`import-ps1`)

---


## ⚙️ Requirements

- Python 3 + install requirements.txt
- Bash + dig + xxd (for Linux client)
- PowerShell 4.0 (for Windows client)

Install dependencies:

```bash
pip install -r requirements.txt
```


## 🚀 Usage

```bash
python3 NekoDNS.py -h             

  _   _      _         ____  _   _ ____  
 | \ | | __ | | __ __ |  _ \| \ | / ___| 
 |  \| |/ _ \ |/ / _ \| | | |  \| \___ \ 
 | |\  |  __/   < (_) | |_| | |\  |___) |
 |_| \_|\___|_|\_\___/|____/|_| \_|____/ 
                                         
                                               
  ----------- by @JoelGMSec -----------

[!] Usage: python3 NekoDNS.py <listen_ip> <listen_port> <-udp/-tcp>

```

**Arguments**:
- `<listen_ip>`: IP address to listen (0.0.0.0 by default)  
- `<listen_port>`: Port to listen (53 by default)  
- `<-udp/-tcp>`: Protocol to use (UDP or TCP)  

**Available Commands**:
- `upload "local_file" "remote_file"`: → Upload a file to the client
- `download "remote_file" "local_file"`: → Download a file from the client
- `import-ps1 "script.ps1"`: → Import a PowerShell script on Windows clients
- `sudo "command"`: → Execute with elevated privileges on Linux
- `clear / cls`: → Clear terminal screen
- `kill`: → Kill the client connection
- `exit`: → Close the session 

## 📸 Screenshots

<img width="1263" height="816" alt="image" src="https://github.com/user-attachments/assets/ab5143a5-04e2-4cc8-8cf9-26ab766493d7" />


## 🗂️ Documentation

The detailed guide of use can be found at the following link:
https://darkbyte.net/nekodns-jugando-con-dns-una-vez-mas


## 📄 License

This project is licensed under the GNU GPL-3.0 license - See the LICENSE file for more details.


## 👨‍💻 Contact

For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) 

Other ways to contact me on my blog [darkbyte.net](https://darkbyte.net)


## ⚠️ Disclaimer

This software comes with no warranty, it is intended exclusively for educational purposes and authorized security audits.

The author is not responsible for any misuse or damage caused by this software.

# ☕ Support
Support my work by buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
