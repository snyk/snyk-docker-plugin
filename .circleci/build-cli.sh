#! /bin/bash

echo "Cloning CLI repo"
cd ~
git clone https://github.com/snyk/cli.git
cd cli
echo "Replacing snyk-docker-plugin dependency with SHA $CIRCLE_SHA1"
sed -iE  "s/\"snyk-docker-plugin\": \".*\",/\"snyk-docker-plugin\": \"git:\/\/github.com\/snyk\/snyk-docker-plugin.git#$CIRCLE_SHA1\",/" package.json
sudo npm i -g npm@7
echo "Running npm install"
npm i
echo "Running build"
npm run build
