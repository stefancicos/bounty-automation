#!/bin/bash

#ARGS

domain=$1

#Setup
echo "==========================================" | notify
echo "\`\`\`Automated vulnerability scanner started\`\`\`" | notify
echo "==========================================" | notify
mkdir -p $domain $domain/subdomains $domain/scanners $domain/intel

sublist3r -d $domain -o $domain/subdomains/sublist3r.txt & subfinder -d $domain -o $domain/subdomains/subfinder.txt & assetfinder -subs-only $domain -v | tee $domain/subdomains/assetfinder.txt & gobuster dns -t 1000 -w ./all.txt -d $domain -o $domain/subdomains/gobusterdns.txt & wait

cat $domain/subdomains/*.txt > $domain/subdomains/all.txt
sort $domain/subdomains/all.txt | uniq -u $domain/subdomains/all.txt > $domain/subdomains/output.txt
cat $domain/subdomains/output.txt | sed 's/www.//' > $domain/subdomains/nowww.txt
sort $domain/subdomains/nowww.txt | uniq > $domain/subdomains/subdomains.txt
httpx -l $domain/subdomains/subdomains.txt -o $domain/subdomains/httpx.txt
cat $domain/subdomains/httpx.txt | sed 's/http[s]\?:\/\///' > $domain/subdomains/nmap_formatted_list.txt
cd $domain/subdomains/
rm sublist3r.txt
rm subfinder.txt
rm assetfinder.txt
rm all.txt
rm output.txt
rm nowww.txt
rm subdomains.txt
rm gobusterdns.txt
cd ../../

echo "\`\`\`Subdomain enumeration ended\`\`\`" | notify
nikto_scan(){
nikto -h http://$domain -o $domain/scanners/nikto.txt
echo "\`\`\`Nikto scan ended\`\`\`" | notify
}
nmap_scan(){
nmap --script vuln -iL $domain/subdomains/nmap_formatted_list.txt -o $domain/scanners/nmap.txt
echo "\`\`\`Nmap scan ended\`\`\`" | notify
}
nuclei_scan(){
nuclei -t ./templates/ -o $domain/scanners/nuclei.txt -l $domain/subdomains/httpx.txt
echo "\`\`\`Nuclei scan ended\`\`\`" | notify
}
param_reflection(){
python3 ./ParamSpider/paramspider.py -d $domain | sed 's/FUZZ//'  > $domain/intel/paramspider.txt
cat paramspider.txt | Gxss  > $domain/intel/reflected_parameters.txt
echo "\`\`\`Reflected parameters scan ended\`\`\`" | notify
}
xss_check(){
dalfox file $domain/subdomains/httpx.txt --mass > $domain/scanners/dalfox.txt 
dalfox file $domain/intel/reflected_parameters.txt --mass > $domain/scanners/dalfox_reflected.txt
echo "\`\`\`Dalfox scan ended\`\`\`" | notify
}
param_reflection
nikto_scan & nmap_scan & nuclei_scan & xss_check & wait
