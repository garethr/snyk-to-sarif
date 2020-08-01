FROM python:slim

ADD snyk-to-sarif.py /snyk-to-sarif.py

WORKDIR /app

ENTRYPOINT ["/snyk-to-sarif.py"]
CMD ["--help"]
