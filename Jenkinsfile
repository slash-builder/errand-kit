// CI for the Errand Kit: every push and pull request runs the gates in scripts/ci.sh inside a pinned Rust image.
// fmt, clippy -D warnings, tests (default and no default features), docs with warnings denied, cargo-deny (supply chain),
// the hygiene gate (nothing internal may ship) and a package dry run. Nothing is published from here: a release is a deliberate
// act (Jenkinsfile.release), never a side effect of merging (Rust and crates.io standard, section 5).
def RUST_IMAGE = 'rust:1.94'
def DENY_VERSION = '0.20.2'
def DENY_SHA256 = '9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f'   // cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz

pipeline {
  agent { label 'linux-build' }

  options {
    timeout(time: 30, unit: 'MINUTES')
    timestamps()
    disableConcurrentBuilds(abortPrevious: true)
  }

  environment {
    CARGO_HOME = "/tmp/cargo-home"   // outside the workspace: nothing cargo caches (advisory db, registry) can end up in a package
  }

  stages {
    stage('Gates') {
      agent { docker { image RUST_IMAGE; args '-u root'; reuseNode true } }
      steps {
        sh """
          set -eu
          # cargo-deny: the pinned prebuilt release, verified by checksum (not compiled on every run, not trusted unverified).
          arch=\$(uname -m)
          if [ "\$arch" = "x86_64" ]; then
            curl -fsSLo /tmp/deny.tgz "https://github.com/EmbarkStudios/cargo-deny/releases/download/${DENY_VERSION}/cargo-deny-${DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz"
            echo "${DENY_SHA256}  /tmp/deny.tgz" | sha256sum -c -
            tar -xzf /tmp/deny.tgz -C /tmp
            install -m 0755 /tmp/cargo-deny-${DENY_VERSION}-x86_64-unknown-linux-musl/cargo-deny /usr/local/bin/cargo-deny
          else
            cargo install cargo-deny --locked --version ${DENY_VERSION}
          fi
          git config --global --add safe.directory "\$WORKSPACE"
          REQUIRE_DENY=1 bash scripts/ci.sh
        """
      }
      post {
        always { sh 'chown -R "$(stat -c "%u:%g" "$WORKSPACE/.git")" "$WORKSPACE" 2>/dev/null || true' }
      }
    }
  }

  post {
    always { cleanWs() }
  }
}
