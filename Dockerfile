FROM registry.cn-shenzhen.aliyuncs.com/vergil-private/python:3.12.7-alpine3.19

LABEL maintainer="vergilheyeahfun@gmail.com"


ARG ALI_MIRROR=https://mirrors.aliyun.com/pypi/simple/
WORKDIR /app

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

COPY requirements.txt .
RUN pip install -r requirements.txt -i ${ALI_MIRROR}
COPY requirements.txt .
COPY ecs_sg_manager.py .
COPY utils/ ./utils/
COPY configurations/ ./configurations/
COPY ip-addresses.txt .

RUN mkdir -p /app/logs

RUN pip install --no-cache-dir -r requirements.txt

RUN apk add --no-cache tzdata
ENV TZ=Asia/Shanghai

COPY crontab /etc/cron.d/sg-manager
RUN chmod 0644 /etc/cron.d/sg-manager

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
