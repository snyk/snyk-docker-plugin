FROM centos:centos7

RUN \
  curl -fsSL https://rpm.nodesource.com/setup_10.x | bash - \
  && curl -fsSLo /etc/yum.repos.d/yarn.repo https://dl.yarnpkg.com/rpm/yarn.repo \
  && yum clean all

ENV \
  NODE_VER=10.15.3-1nodesource \
  npm_config_unsafe_perm=true

RUN \
  yum install -y "nodejs-${NODE_VER}" yarn make gcc-c++ \
  && yum clean all

CMD [ "node" ]
