# Internal AB#758 feasibility image. It is not a customer catalog image.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/home/trial \
    LANG=C.UTF-8 \
    XDG_RUNTIME_DIR=/tmp/hyprland-runtime \
    HYPRLAND_NO_RT=1 \
    LIBGL_ALWAYS_SOFTWARE=1

RUN printf '%s\n' 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/trixie-backports.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       hyprland=0.55.2+ds-1~bpo13+1 wayvnc vncdotool foot procps python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --create-home --home-dir /home/trial --shell /bin/sh trial

COPY --chmod=0755 probe.sh /usr/local/bin/hyprland-trial-probe

USER trial
WORKDIR /home/trial
CMD ["sleep", "infinity"]
