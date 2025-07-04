FROM python:3.12-alpine

RUN apk update && apk add git

RUN git clone https://github.com/TitleOS/ADBNectar.git

WORKDIR /hive

COPY adbnectar /adbnectar
COPY adbnectar.cfg adbnectar.cfg
COPY run.py run.py
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x /run.py

EXPOSE 5555


CMD ["python", "run.py"]
