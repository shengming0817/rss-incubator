ARG MOSQUITTO_IMAGE=eclipse-mosquitto:2.0.22-openssl@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c

FROM ${MOSQUITTO_IMAGE} AS runtime

FROM ${MOSQUITTO_IMAGE} AS build
USER root
RUN apk add --no-cache build-base curl openssl-dev
WORKDIR /deps
RUN curl -fsSL https://github.com/eclipse-mosquitto/mosquitto/archive/refs/tags/v2.0.22.tar.gz \
      -o mosquitto.tar.gz \
 && echo "a2850bd168cd9f1baa954c30994167f9f8c54ee4966ef34738620a48f63657d5  mosquitto.tar.gz" \
      | sha256sum -c - \
 && tar xzf mosquitto.tar.gz \
 && cp mosquitto-2.0.22/include/mosquitto.h /usr/include/ \
 && cp mosquitto-2.0.22/include/mosquitto_broker.h /usr/include/ \
 && cp mosquitto-2.0.22/include/mosquitto_plugin.h /usr/include/ \
 && cp mosquitto-2.0.22/include/mqtt_protocol.h /usr/include/
COPY --from=runtime /usr/lib/libmosquitto.so.1 /usr/lib/libmosquitto.so.1
RUN ln -s libmosquitto.so.1 /usr/lib/libmosquitto.so
WORKDIR /src
COPY plugin.c /src/plugin.c
RUN cc -std=c17 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
      -Wall -Wextra -Werror -fPIC -shared /src/plugin.c \
      -Wl,-z,relro -Wl,--allow-shlib-undefined \
      -lcrypto -lmosquitto -o /rss_mqtt_command_assertion.so

FROM ${MOSQUITTO_IMAGE}
COPY --from=build /rss_mqtt_command_assertion.so /usr/lib/rss_mqtt_command_assertion.so
