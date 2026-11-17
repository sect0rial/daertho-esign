FROM python:3.12-slim

# LibreOffice turns uploaded Word/ODT/RTF files into PDF; the fonts make contracts lay out as they do in Word
# (Liberation = Arial/Times/Courier metrics, Carlito/Caladea = Calibri/Cambria, Noto = most scripts incl. CJK).
# Build with --build-arg WITH_OFFICE=0 for a much smaller image that accepts PDFs and images only.
#
# Sandbox: the API runs as root ONLY so it can start LibreOffice as the unprivileged `esignconv` account, which
# cannot read the code, the data volume or the API's environment (ESIGN_SECRET). A hostile document therefore
# can't reach anything that matters even if it exploits the converter.
ARG WITH_OFFICE=1
RUN apt-get update \
 && if [ "$WITH_OFFICE" = "1" ]; then apt-get install -y --no-install-recommends \
      libreoffice-writer-nogui fonts-liberation fonts-crosextra-carlito fonts-crosextra-caladea \
      fonts-dejavu-core fonts-noto-core fonts-noto-cjk; fi \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin esignconv

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY esign ./esign
COPY scripts ./scripts
RUN chmod 0750 /app && mkdir -p /data && chmod 0700 /data

ENV ESIGN_DATA_DIR=/data PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
# uvicorn is NOT told to trust proxy headers: the client IP recorded as evidence comes from ESIGN_TRUST_PROXY handling in the app, which
# only believes the hop your own proxy appended.
CMD ["sh", "-c", "exec uvicorn esign.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
