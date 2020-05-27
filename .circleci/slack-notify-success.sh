#! /bin/bash

curl -X POST -H 'Content-Type:application/json' -d '{"attachments": [{"color": "#7CD197", "fallback": "Build Notification: '$CIRCLE_BUILD_URL'", "title": "Snyk-Docker-Plugin Publish Notification", "text": ":krotik-yay: Snyk-Docker-Plugin Was Published :krotik-yay:"}]}' $SLACK_WEBHOOK
