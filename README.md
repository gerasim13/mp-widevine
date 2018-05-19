widevine-proxy issuer
Deploy needed services to playback a ciphered content
There are 5 services (apps):
    encoder (ffmpeg)
    packager (shaka-packager)
    cdn (Apache)
    proxy (widevine-proxy)
    keys (get keys from google license server)

1. Set environment variables

EXTERNAL_KEYS=true (if used Google server to retrieve keys)
EXTERNAL_KEYS=false (if used own internal KMS to retrieve keys)

2. Build the all services:

docker-compose build

3. Run service:

docker-compose run encoder
docker-compose run packager
docker-compose up -d proxy
docker-compose up -d cdn
docker-compose up keys

4. URLs:

proxy: https://localhost:6060

cdn: http://localhost:8080

5. Get logging from each service:

docker-compose logs -t -f <service_name>

6. URL Shaka player

Use incognito window (due to autosigned certificate)
https://shaka-player-demo.appspot.com


