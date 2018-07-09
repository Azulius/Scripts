#!/bin/bash
CIDR=10.11.1.0/24
NETBLK=10.11.1.
INTERFACE=tap0
CURDIR=$(pwd)
NETNAME=Student
mkdir $CURDIR/$NETNAME
WKDIR=$CURDIR/$NETNAME

# Run nmap sweep
nmapsweep() {
nmap -sn $CIDR -oG $WKDIR/nmap-sweep.txt > /dev/null
cat $WKDIR/nmap-sweep.txt |grep Up |awk '{print$2}' > $WKDIR/totalhosts.txt
NSH=$(cat $WKDIR/totalhosts.txt |sort |uniq |wc -l)
echo "[*] NMAP sweeps identified" $NSH "hosts."
}

# Run normal ping sweep
pingsweep() {
for ip in $(seq 1 254); do
ping -c 1 $NETBLK$ip |grep "bytes from" 1>> $WKDIR/pingsweep.txt&
done
sleep 5
cat $WKDIR/pingsweep.txt |cut -d" " -f 4 |cut -d ":" -f1 >> $WKDIR/totalhosts.txt

PSH=$(cat $WKDIR/pingsweep.txt |sort |uniq |wc -l)
echo "[*] Ping sweep identified" $PSH "hosts."
}

# Displays the kernel's IPv4 network neighbour cache
arpscan() {
arp -a -i $INTERFACE |grep -v incomplete > $WKDIR/arp.txt
cat $WKDIR/arp.txt |awk '{print$2}' |awk -F ")" '{print$1}' |awk -F "(" '{print$2}' >> $WKDIR/totalhosts.txt

ARPH=$(cat $WKDIR/arp.txt |sort |uniq |wc -l)
echo "[*] ARP identified" $ARPH "hosts."
}

# Scan for hosts with SMB/Netbios
smbscan() {
nbtscan $CIDR > $WKDIR/nbtscan.txt
cat $WKDIR/nbtscan.txt |grep ^$NETBLK |awk '{print$1}' >> $WKDIR/totalhosts.txt
cat $WKDIR/nbtscan.txt |grep ^$NETBLK |awk '{print$1}' >> $WKDIR/smbhosts.txt

SMBH=$(cat $WKDIR/smbhosts.txt |sort |uniq |wc -l)
echo "[*] Identifed" $SMBH "SMB hosts."
}

# NMAP Scan for common http ports
webscan(){
nmap -p 80 $CIDR --open -oG $WKDIR/web80-sweep.txt > /dev/null
nmap -p 443 $CIDR --open -oG $WKDIR/web443-sweep.txt > /dev/null
nmap -p 8080 $CIDR --open -oG $WKDIR/web8080-sweep.txt > /dev/null
WSH=$(cat $WKDIR/web*.txt |grep open |sort |uniq |wc -l)
echo "[*] Identified" $WSH "web servers."
}

# Sorts and cleans up output files and IP lists, removes duplicates and also creates the directories for identified hosts
cleanup(){

cat $WKDIR/web80-sweep.txt |grep open |awk '{print$2}' |sort |uniq |grep $NETBLK > $WKDIR/hosts_80.txt
cat $WKDIR/hosts_80.txt >> $WKDIR/totalhosts.txt
rm $WKDIR/web80-sweep.txt

cat $WKDIR/web443-sweep.txt |grep open |awk '{print$2}' |sort |uniq |grep $NETBLK > $WKDIR/hosts_443.txt
cat $WKDIR/hosts_443.txt >> $WKDIR/totalhosts.txt
rm $WKDIR/web443-sweep.txt

cat $WKDIR/web8080-sweep.txt |grep open |awk '{print$2}' |sort |uniq |grep $NETBLK > $WKDIR/hosts_8080.txt
cat $WKDIR/hosts_8080.txt >> $WKDIR/totalhosts.txt
rm $WKDIR/web8080-sweep.txt

cat $WKDIR/totalhosts.txt |sort |uniq |grep $NETBLK > $WKDIR/all_hosts.txt
rm $WKDIR/totalhosts.txt

THOS=$(cat $WKDIR/all_hosts.txt |sort |uniq |wc -l)
echo "[*] Unique Hosts Identifed:" $THOS

for host in $(cat $WKDIR/all_hosts.txt); do
	mkdir $WKDIR/$host
done

echo "[*] Created" $THOS "host direcories in" $WKDIR"."

}

nmapfull(){
for host in $(cat $WKDIR/all_hosts.txt); do
	nmap -sV -sC -oA $WKDIR/$host/nmap $host > /dev/null
done
echo "[*] NMAP Fingerprinting and NSE has completed."
}

dirbscan(){
for host in $(cat $WKDIR/hosts_80.txt); do
	dirb http://$host/ -o $WKDIR/$host/dirb.txt > /dev/null
done

for host in $(cat $WKDIR/hosts_443.txt); do
	dirb https://$host/ -o $WKDIR/$host/dirb.txt > /dev/null
done

for host in $(cat $WKDIR/hosts_8080.txt); do
	dirb http://$host/ -o $WKDIR/$host/dirb.txt > /dev/null
done
echo "[*] DIRB Scan of all web servers has completed."
}

niktoscan(){
for host in $(cat $WKDIR/hosts_80.txt); do
	nitko -h http://$host/ > $WKDIR/$host/nikto.txt 2> /dev/null
done

for host in $(cat $WKDIR/hosts_443.txt); do
	nitko -h https://$host/ > $WKDIR/$host/nikto.txt 2> /dev/null
done

for host in $(cat $WKDIR/hosts_8080.txt); do
	nitko -h http://$host/ > $WKDIR/$host/nikto.txt 2> /dev/null
done
echo "[*] Nikto Scan of all web servers has completed."
}

nmaphttp(){
for host in $(cat $WKDIR/all_hosts.txt); do
	xsltproc $WKDIR/$host/nmap.xml -o $WKDIR/$host/nmap.html 2> /dev/null
done
echo "[*] NMAP HTML reports are ready. "
}

enumsmb(){
for host in $(cat $WKDIR/smbhosts.txt); do
	enum4linux -a $host > $WKDIR/$host/enum4linux.txt 2> /dev/null
done
echo "[*] SMB Enumeration has completed."
}

#Discovery Phase Functions
#nmapsweep
#pingsweep
#arpscan
#smbscan
#webscan

#Cleaning up Function
#cleanup

# Server/Banner Enumeration
#nmapfull
#nmaphttp
dirbscan
niktoscan
enumsmb
