FROM python:3.12-alpine

RUN apk update && apk add git

RUN git clone https://github.com/TitleOS/ADBNectar.git

WORKDIR /ADBNectar
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
