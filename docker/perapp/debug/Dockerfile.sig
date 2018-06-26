FROM scion_sig:latest
COPY --from=scion_debug_base:latest / /
