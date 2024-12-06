## Cloud-vendor-sg-manager
![Python 3.12](https://img.shields.io/badge/PYTHON-3.12-red)
![SHELL](https://img.shields.io/badge/SHELL-blue)


### Install environment
```Python3
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools
python3 -m pip install wheel
python3 -m pip install -r requirements.txt
```

### Change configuration file
Write your access keyid and secret key in `ali_sg/account.csv`

### Usage
```Shell
cd ali_sg/ && python3 ecs_sg_manager.py
```