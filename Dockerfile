# syntax=docker/dockerfile:1
# Digests iguais aos de versions.lock (2026-10-03).

ARG DEBIAN_DIGEST=sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG GOLANG_DIGEST=sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5

FROM golang:1.27.1-trixie@${GOLANG_DIGEST} AS sourcebins
ARG ASSETFINDER_COMMIT=4e95d8701aae8cff1c27af2626eb22ba110ad583
ARG WAYBACKURLS_VERSION=0.1.0
ARG TEMPLATES_COMMIT=893122ffce8ebf8e264f15d2cd3960cb1dd36d6c
ENV GOTOOLCHAIN=local
WORKDIR /src

RUN git clone --depth 1 --branch v0.1.1 https://github.com/tomnomnom/assetfinder.git assetfinder \
    && test "$(git -C assetfinder rev-parse HEAD)" = "${ASSETFINDER_COMMIT}" \
    && cd assetfinder \
    && go mod init github.com/tomnomnom/assetfinder \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/assetfinder .

RUN GOBIN=/out CGO_ENABLED=0 go install "github.com/tomnomnom/waybackurls@v${WAYBACKURLS_VERSION}"

RUN git clone --depth 1 --branch v10.4.9 https://github.com/projectdiscovery/nuclei-templates.git /out/nuclei-templates \
    && test "$(git -C /out/nuclei-templates rev-parse HEAD)" = "${TEMPLATES_COMMIT}" \
    && rm -rf /out/nuclei-templates/.git \
    && printf '%s\n' "${TEMPLATES_COMMIT}" > /out/nuclei-templates/.commit

FROM debian:13-slim@${DEBIAN_DIGEST} AS releasetools
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip tar \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
COPY versions.lock /tmp/versions.lock
COPY scripts/fetch-tools.sh /tmp/fetch-tools.sh
RUN bash /tmp/fetch-tools.sh

FROM debian:13-slim@${DEBIAN_DIGEST}
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        findutils \
        gawk \
        grep \
        jq \
        python3 \
        python3-pip \
        python3-venv \
        sed \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/recon/venv

COPY --from=releasetools /out/bin/ /usr/local/bin/
COPY --from=sourcebins /out/assetfinder /usr/local/bin/assetfinder
COPY --from=sourcebins /out/waybackurls /usr/local/bin/waybackurls
COPY --from=sourcebins /out/nuclei-templates /opt/nuclei-templates
COPY versions.lock /opt/recon/versions.lock
COPY scripts/common.sh /usr/local/lib/recon/common.sh
COPY scripts/verify-image.sh /usr/local/lib/recon/verify-image.sh
COPY recon-claude-grok.sh /usr/local/bin/recon-claude-grok.sh
COPY requirements.txt /opt/recon/requirements.txt
COPY recon_ai /opt/recon/app/recon_ai

RUN /opt/recon/venv/bin/pip install --no-cache-dir -r /opt/recon/requirements.txt \
    && chmod 755 /usr/local/lib/recon/verify-image.sh /usr/local/bin/recon-claude-grok.sh \
        /usr/local/bin/subfinder /usr/local/bin/amass /usr/local/bin/assetfinder \
        /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/katana \
        /usr/local/bin/gau /usr/local/bin/waybackurls /usr/local/bin/nuclei \
        /usr/local/bin/go-dork \
    && chmod 644 /usr/local/lib/recon/common.sh /opt/recon/versions.lock \
    && chmod -R a+rX /opt/nuclei-templates \
    && sha256sum \
        /usr/local/bin/assetfinder \
        /usr/local/bin/amass \
        /usr/local/bin/dnsx \
        /usr/local/bin/gau \
        /usr/local/bin/go-dork \
        /usr/local/bin/httpx \
        /usr/local/bin/katana \
        /usr/local/bin/nuclei \
        /usr/local/bin/subfinder \
        /usr/local/bin/waybackurls \
        > /opt/recon/bin-sha256.txt \
    && chmod a+r /opt/recon/bin-sha256.txt

WORKDIR /results
ENV PYTHONPATH=/opt/recon/app
ENV RECON_DB=/results/recon.db
ENV RECON_STATE_HOME=/results/state/home
ENV RECON_VERIFY=/usr/local/lib/recon/verify-image.sh
ENTRYPOINT ["/opt/recon/venv/bin/python", "-m", "recon_ai"]
