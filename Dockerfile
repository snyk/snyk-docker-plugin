FROM nginx:1.18.0

RUN echo "Bye"

RUN apk add openssl@1.5.0

CMD ["nginx"]
