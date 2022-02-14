# parseISO8583
Parse traffic file from wireshark or tcpdump and extract ISO 8583 Base 1 messages

## Install

This is a virtual env python project, only need create virtual env, for example in my home work dir

```console
python3 -m venv /home/jloja/Aplicaciones/parseISO8583
```

For requirements we need activate virtualenv

```console
cd parseISO8583
source bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

For run you need have activated the virtual env and then

```console
python3 extract.py  --pcap <file>
```