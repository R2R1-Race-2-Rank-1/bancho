FROM python:3.7-bullseye

WORKDIR /pep.py
COPY . .

# Install dependencies in a single layer to reduce image size
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    default-mysql-client \
    default-libmysqlclient-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install any needed packages specified in requirements.txt
RUN pip3 install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt

RUN python3.7 setup.py build_ext --inplace

CMD ["python3.7", "-u", "pep.py"]
