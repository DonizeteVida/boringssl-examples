# BUILT USING ECLIPSE IDE

openssl ecparam -name prime256v1 -genkey -noout -out priv.pem

openssl ec -in priv.pem -pub out -out pub.pem