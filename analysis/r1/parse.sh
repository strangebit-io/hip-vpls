cat hipls.log| grep "IPSEC recv" | awk -F" " '{print $7}' > IPSECrecv.txt
cat hipls.log| grep "IPSEC process" | awk -F" " '{print $7}' > IPSECprocess.txt
cat hipls.log| grep "IPSEC send" | awk -F" " '{print $7}' > IPSECsend.txt      
cat hipls.log| grep "Ethernet recv" | awk -F" " '{print $7}' > L2recv.txt     
cat hipls.log| grep "L2 process" | awk -F" " '{print $7}' > L2process.txt    
cat hipls.log| grep "L2 send" | awk -F" " '{print $7}' > L2send.txt   


R --slave < stats.R
