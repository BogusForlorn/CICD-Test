FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git curl wget unzip docker.io \
    openjdk-17-jre-headless \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.50.4/trivy_0.50.4_Linux-64bit.tar.gz \
    | tar -xzf - -C /usr/local/bin trivy && chmod +x /usr/local/bin/trivy

# Install Gitleaks
RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar -xzf - -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks

# Install Checkov
RUN pip install --no-cache-dir checkov==3.2.0

# Install OWASP ZAP (headless)
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz \
    -O /tmp/zap.tar.gz && tar -xzf /tmp/zap.tar.gz -C /opt && \
    ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap.sh && \
    ln -s /opt/ZAP_2.14.0/zap-full-scan.py /usr/local/bin/zap-full-scan.py && \
    ln -s /opt/ZAP_2.14.0/zap-baseline.py /usr/local/bin/zap-baseline.py && \
    rm /tmp/zap.tar.gz

# Install Semgrep and Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV WORKSPACE=/workspace
ENV RESULTS_DIR=/results

CMD ["python3", "run_scans.py"]
