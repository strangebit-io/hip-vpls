# Removing unused folder
sudo rm -rf mininet

# Cloning the database
git clone git://github.com/mininet/mininet
cd mininet
git tag  # list available versions
git checkout -b mininet-2.3.0 2.3.0  # or whatever version you wish to install
cd ..

# Installing the mininet globally
sudo PYTHON=python3 mininet/util/install.sh -a

# Running the VPLS emulated environment
cd hip-vpls
sudo python3 hipls-mn.py



