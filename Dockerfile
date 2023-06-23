FROM python:3.9.16 as setup

COPY . .
RUN ./setup.py sdist bdist_wheel

FROM python:3.9.16

LABEL Remarks="NTT IRRD4"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    postgresql-client && \
    apt-get -y clean && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt/lists/*

COPY wait-for-postgres.sh /usr/bin/

RUN chmod +x /usr/bin/wait-for-postgres.sh

COPY entrypoint.sh /usr/bin/

RUN chmod +x /usr/bin/entrypoint.sh

RUN groupadd -r -g 777 irrd && useradd -m -r -u 777 -g irrd irrd

USER irrd

RUN python -m venv /home/irrd/irrd-venv

RUN /home/irrd/irrd-venv/bin/pip install --no-cache-dir --upgrade pip

COPY --from=setup dist/irrd-*.tar.gz /tmp/irrd.tar.gz

RUN /home/irrd/irrd-venv/bin/pip install --no-cache-dir file:///tmp/irrd.tar.gz

USER root

RUN rm -rf /tmp/irrd.tar.gz

USER irrd

ENTRYPOINT ["/usr/local/bin/tini", "--", "entrypoint.sh"]
