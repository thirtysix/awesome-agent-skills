FROM localhost/aas-base
COPY yr /usr/local/bin/yr
COPY rules /opt/yara-forge
ENTRYPOINT ["yr"]
