docker build . -t super.gtisc.gatech.edu/s2e:latest

docker login super.gtisc.gatech.edu --username=gtisc --password=Dock3r_reg1stry_f0r_Gt1sc
docker push super.gtisc.gatech.edu/s2e:latest
docker logout super.gtisc.gatech.edu