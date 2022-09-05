sudo chmod 777 /var/run/docker.sock
docker run -d --name dlm -p 8080:8080 cain19811028/go-azure-ad
export PUBLIC_IP=`dig +short myip.opendns.com @resolver1.opendns.com`
docker exec -it dlm sed -i "s~REDIRECT_URI=http://localhost~REDIRECT_URI=https://$PUBLIC_IP~g" .env
docker restart dlm
