FROM python:3.12-alpine

RUN apk update && apk add git

RUN git clone https://github.com/TitleOS/ADBNectar.git

WORKDIR /ADBNectar
COPY entrypoint.sh /ADBNectar/entrypoint.sh
COPY adbnectar.cfg /ADBNectar/adbnectar.cfg 
RUN chmod +x /entrypoint.sh

EXPOSE 5555

ENTRYPOINT ["/entrypoint.sh"]
