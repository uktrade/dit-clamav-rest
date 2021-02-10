FROM python:3.9.1-buster

ENV PORT 8090
EXPOSE $PORT

ENV WORKDIR /srv/clamav-rest

WORKDIR $WORKDIR
ADD . $WORKDIR

RUN pip install -r requirements.txt

CMD ["/bin/bash", "/srv/clamav-rest/run.sh"]
