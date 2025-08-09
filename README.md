# Prepare environment for Python script execution
```
#!/bin/bash
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install BeautifulSoup
python main.py
```

to launch with docker:

```
docker run -v [YOUR TXT LINKS]:/app/input.txt -v [FOLDER TO RECIVE GAMES]:/app/downloads vimm:latest
```
