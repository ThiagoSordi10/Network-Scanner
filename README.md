# Network Scanner

Python script to detect devices on network.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install packages at requirements.txt.

```bash
pip install -r requirements.txt
```

And install Npcap (https://nmap.org/npcap/), if in Windows, just download and install.

## Usage

First, change IFACE_NAME variable with the name of your network card (```ipconfig /all``` in CMD)

```python

IFACE_NAME = "Intel(R) Wireless-AC 9560 160MHz"
MAC_URL = 'http://macvendors.co/api/%s'

data_lock = Lock()
```

Then, you could use just running.

```bash
python main.py
```

## Authors
<a href="https://github.com/GuilhermePretto">Guilherme Pretto</a>, <a href="https://github.com/smfinkler">Samuel Finkler</a>, Thiago Sordi

## License
[MIT](https://choosealicense.com/licenses/mit/)
