git clone git://github.com/mininet/mininet
cd mininet
git tag  # list available versions
git checkout -b mininet-2.3.0 2.3.0  # or whatever version you wish to install
cd ..

bash sudo PYTHON=python3 mininet/util/install.sh -n
sudo mn --switch ovsbr --test pingall



