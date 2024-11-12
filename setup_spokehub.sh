# Description: This script copies the necessary files from spoke 1 and hub 1 to spoke 2, 3 and hub 2, 3 respectively.
project="./" # Path to project folder
s1="/spoke1/hiplib"
s2="/spoke2/hiplib"
s3="/spoke3/hiplib"
h1="/hub1/hiplib"
h2="/hub2/hiplib"
h3="/hub3/hiplib"


# Copy hlib.py file from spoke 1 to spoke 2 3
for i in ${project}${s2}/hlib.py ${project}${s3}/hlib.py
do 
	sudo cp ${project}${s1}/hlib.py $i
done 

# Copy hlib.py file from hub 1 to hub 2 3
for i in ${project}${h2}/hlib.py ${project}${h3}/hlib.py
do 
	sudo cp ${project}${h1}/hlib.py $i
done 

# Copy switchd.py file from spoke 1 to spoke 2 3
for i in ${project}/spoke2/switchd.py ${project}/spoke3/switchd.py
do 
	sudo cp ${project}/spoke1/switchd.py $i
done 

# Copy switchd.py file from hub 1 to hub 2 3
for i in ${project}/hub2/switchd.py ${project}/hub3/switchd.py
do 
	sudo cp ${project}/hub1/switchd.py $i
done

# Copy relevant folders from spoke 1 to spoke 2 3
for f in crypto packets databases
do
	for i in ${project}${s2}/${f} ${project}${s3}/${f}
	do 
		sudo cp -r -T ${project}${s1}/${f} $i
	done 
done

for f in crypto packets databases
do
	for i in ${project}${h2}/${f} ${project}${h3}/${f}
	do 
		sudo cp -r -T ${project}${h1}/${f} $i
	done 
done
echo "Finished copying hubs & spokes."