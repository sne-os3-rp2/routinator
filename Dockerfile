# -- stage 1: build static routinator with musl libc for alpine
FROM alpine:3.11.6 as build

RUN apk add rust cargo

WORKDIR /tmp/routinator
COPY . .

RUN cargo build \
    --target x86_64-alpine-linux-musl \
    --release \
    --locked

# -- stage 2: create alpine-based container with the static routinator
#             executable
FROM alpine:3.11.6
COPY --from=build /tmp/routinator/target/x86_64-alpine-linux-musl/release/routinator /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=routinator
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install rsync as routinator depends on it
RUN apk add --no-cache rsync libgcc

# Use Tini to ensure that Routinator responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
RUN apk add --no-cache tini
# Tini is now available at /sbin/tini

RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the repository and TAL directories
RUN mkdir -p /home/${RUN_USER}/.rpki-cache/repository /home/${RUN_USER}/.rpki-cache/tals && \
    chown -R ${RUN_USER_UID}:${RUN_USER_GID} /usr/local/bin/routinator /home/${RUN_USER}/.rpki-cache

# Adding IPFS

#Install IPFS
WORKDIR /tmp/ipfs
RUN mkdir go-ipfs
COPY ./go-ipfs ./go-ipfs
RUN cd ./go-ipfs && ./install.sh
RUN apk add libc6-compat

# Expose ports
# Swarm TCP; should be exposed to the public
EXPOSE 4001
# Swarm UDP; should be exposed to the public
EXPOSE 4001/udp
# Daemon API; must not be exposed publicly but to client services under you control
EXPOSE 5001
# Web Gateway; can be exposed publicly with a proxy, e.g. as https://ipfs.example.org
EXPOSE 8080
# Swarm Websockets; must be exposed publicly when the node is listening using the websocket transport (/ipX/.../tcp/8081/ws).
EXPOSE 8081

# Create the fs-repo directory and switch to a non-privileged user.
ENV IPFS_PATH /data/ipfs
RUN mkdir -p $IPFS_PATH \
  && chown ${RUN_USER}:${RUN_USER_GID} $IPFS_PATH

# Create mount points for `ipfs mount` command
RUN mkdir /ipfs /ipns \
  && chown ${RUN_USER}:${RUN_USER_GID} /ipfs /ipns

# Expose the fs-repo as a volume.
# start_ipfs initializes an fs-repo if none is mounted.
# Important this happens after the USER directive so permissions are correct.
VOLUME $IPFS_PATH

# The default logging level
ENV IPFS_LOGGING ""

RUN echo $ENV_SWARM_KEY > $IPFS_PATH/swarm.key

RUN mkdir -p /usr/local/nexus \
    && chown ${RUN_USER}:${RUN_USER_GID} /usr/local/nexus

RUN touch /usr/local/nexus/peerid \
   && chown ${RUN_USER}:${RUN_USER_GID} /usr/local/nexus/peerid

RUN chmod 4755 /usr/local/nexus/peerid


EXPOSE 3323/tcp
EXPOSE 9556/tcp

COPY ./entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh
RUN chown ${RUN_USER_UID}:${RUN_USER_GID} /opt/entrypoint.sh

USER $RUN_USER_UID

#ENTRYPOINT ["/sbin/tini", "--", "routinator"]
ENTRYPOINT ["/sbin/tini", "--", "/opt/entrypoint.sh"]
# Execute the daemon subcommand by default
CMD ["server", "--rtr", "0.0.0.0:3323", "--http", "0.0.0.0:9556"]