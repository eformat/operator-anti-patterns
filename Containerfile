FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN microdnf install -y python3 findutils tar gzip git && microdnf clean all
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz && \
    tar xzf ripgrep-*.tar.gz && mv ripgrep-*/rg /usr/local/bin/ && rm -rf ripgrep-*
WORKDIR /opt/scanner
COPY scan-operator-antipatterns.sh scan-release.sh generate-release-report.py \
     .semgrep-operator-antipatterns.yml SKILL.md RELEASE-SCAN-SKILL.md ./
COPY evaluations/ evaluations/
COPY testdata/ testdata/
RUN chmod +x scan-operator-antipatterns.sh scan-release.sh
ENTRYPOINT ["./scan-operator-antipatterns.sh"]
CMD ["/repo"]
