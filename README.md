# go-azure-ad

```
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/C=TW/ST=TAIWAN/L=Taipei/O=MOXA/OU=SW/CN=cainhc.chen@moxa.com"
```

```
go mod init go-azure-ad
go mod tidy
go mod vendor
```

```
docker build --tag go-azure-ad .
docker tag go-azure-ad cain19811028/go-azure-ad
docker push cain19811028/go-azure-ad

docker rmi -f cain19811028/go-azure-ad
docker rmi -f go-azure-ad

docker pull cain19811028/go-azure-ad
docker run -p 8080:8080 cain19811028/go-azure-ad
```