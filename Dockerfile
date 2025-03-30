FROM golang:buster AS builder
#Install JRE for AAPT2

ARG JDK_VERSION=11

RUN apt-get update && \ 
    apt-get install ca-certificates-java openjdk-${JDK_VERSION}-jre-headless -y && \
    apt-get install -y --no-install-recommends openjdk-${JDK_VERSION}-jdk && \
    apt-get install aapt -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/oracle-jdk${JDK_VERSION}-installer && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/src.zip && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/lib/missioncontrol && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/lib/visualvm && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/lib/*javafx* && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/plugin.jar && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/ext/jfxrt.jar && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/bin/javaws && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/javaws.jar && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/desktop && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/plugin && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/deploy* && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/*javafx* && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/*jfx* && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libdecora_sse.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libprism_*.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libfxplugins.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libglass.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libgstreamer-lite.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libjavafx*.so && \
    rm -rf /usr/lib/jvm/java-${JDK_VERSION}-openjdk-amd64/jre/lib/amd64/libjfx*.so

    
## Install Ripgrep 
RUN apt-get update && \
    apt-get install -y --no-install-recommends ripgrep && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    
WORKDIR /app

COPY . .

RUN go mod download

ENV GOARCH=arm64
ENV GOOS=linux
ENV CGO_ENABLED=0

RUN go build -v -x -o morf .

EXPOSE 8888