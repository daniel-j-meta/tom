ARG OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw@sha256:03856e24df2c8620901dc2f2100464e2e65b9074f23d501b4d16e42767bd3123
FROM ${OPENCLAW_IMAGE}
USER root
COPY --chown=node:node containers/browser.mjs containers/resolve-secret.mjs /opt/tom/
RUN chmod 0555 /opt/tom/*.mjs
USER node
