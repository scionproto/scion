sudo ./build/hsr -c 0x3 -n 4 -- -p 0xf -T 0 er1-11er1-13 ../gen/ISD1/AD11/er1-11er1-13/topology.conf ../gen/ISD1/AD11/er1-11er1-13/ad.conf

python3 -c 'import sys, yaml, json; json.dump(yaml.load(sys.stdin), sys.stdout, indent=4)' < ../gen/ISD1/AD11/er1-11er1-13/topology.yml  > topology.json
python3 -c 'import sys, yaml, json; json.dump(yaml.load(sys.stdin), sys.stdout, indent=4)' < ../gen/ISD1/AD11/er1-11er1-13/ad.yml  > ad.json
sudo ./build/hsr -c 0x3 -n 4 -- -p 0xf -T 0 er1-13er1-11 ./topology.json ./ad.json
