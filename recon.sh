#!bin/bash

host=$1
wordlist="/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
resolvers="/root/resolvers.txt"
domain_enum(){
for domain in $(cat $host);
do
    mkdir -p $domain $domain/sources $domain/sources/dnsprobe $domain/sources/dns_query $domain/Recon $domain/Recon/sub_takeover $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan
    subfinder -d $domain -o $domain/sources/subfinder.txt
    subdomain $domain | tee $domain/sources/subdomain.txt
    assetfinder -subs-only $domain | tee $domain/sources/domain.txt
    amass enum -passive -d $domain -o  $domain/sources/passive.txt   
    cat $domain/sources/*.txt | tee $domain/sources/tmp.txt
    cat $domain/sources/tmp.txt | sort -u >> $domain/sources/all.txt
    rm $domain/sources/tmp.txt
done
}
domain_enum
dns_probe(){
for domain in $(cat $host);
do
	dnsprobe -l $domain/sources/all.txt -r A -o $domain/sources/dns_query/A.txt
	dnsprobe -l $domain/sources/all.txt -r NS -o $domain/sources/dns_query/NS.txt
	dnsprobe -l $domain/sources/all.txt -r CNAME -o $domain/sources/dns_query/CNAME.txt
	dnsprobe -l $domain/sources/all.txt -r SOA -o $domain/sources/dns_query/SOA.txt
	dnsprobe -l $domain/sources/all.txt -r PTR -o $domain/sources/dns_query/PTR.txt
	dnsprobe -l $domain/sources/all.txt -r MX -o $domain/sources/dns_query/MX.txt
	dnsprobe -l $domain/sources/all.txt -r TXT -o $domain/sources/dns_query/TXT.txt
	dnsprobe -l $domain/sources/all.txt -r AAAA -o $domain/sources/dns_query/AAAA.txt
	dnsprobe -l $domain/sources/all.txt -f simple -o $domain/sources/dns_query/ip.txt
	dnsprobe -l $domain/sources/all.txt -f full -o $domain/sources/dns_query/response.txt
done
}
dns_probe
sub_takeover(){
for domain in $(cat $host);
do
	findomain -t $domain -r | tee $domain/Recon/sub_takeover/domians.txt
	subzy -targets $domain/Recon/sub_takeover/domians.txt | tee $domain/Recon/sub_takeover/vuln.txt
	subjack -w $domain/sources/all.txt -t 100 -timeout 30 -ssl -c /root/go-workspace/src/github.com/haccer/subjack/fingerprints.json  -v 3 -o $domain/Recon/sub_takeover/potential.txt
done
}
sub_takeover
http_prob(){
for domain in $(cat $host);
do
	awk '$0="https://"$0' $domain/sources/all.txt > $domain/Recon/httpx.txt
done
}
http_prob
webtech(){
for domain in $(cat $host);
do
	webtech --ul=$domain/Recon/httpx.txt | tee $domain/Recon/webtech.txt
done
}
wayback_data(){
for domain in $(cat $host);
do
	cat $domain/sources/all.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt
	cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.svg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/wayback/wayback.txt
	rm $domain/Recon/wayback/tmp.txt
done
}
wayback_data
valid_urls(){
for domain in $(cat $host);
do
	ffuf -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt
	cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/valid.txt
	rm $domain/Recon/wayback/valid-tmp.txt
done
}
valid_urls
gf_patterns(){
for domain in $(cat $host);
do
	gf xss $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/xss.txt
	gf sqli $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/sql.txt
done
}
gf_patterns
custom_wordlist(){
for domain in $(cat $host);
do
	cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt
	cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys > $domain/Recon/wordlist/params.txt
done
}
custom_wordlist
get_ip(){
for domain in $(cat $host);
do
	massdns -r /root/resolvers.txt -t A -o S -w $domain/Recon/masscan/results.txt $domain/sources/all.txt
	gf ip $domain/Recon/masscan/results.txt | sort -u > $domain/Recon/masscan/ip.txt
done
}
get_ip
scanner(){
for domain in $(cat $host);
do
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/takeovers/ -o $domain/Recon/nuclei/sub_takeover.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/default-logins/ -o $domain/Recon/nuclei/default_credentials.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/exposed-tokens/ -o $domain/Recon/nuclei/tokens.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/dns/ -o $domain/Recon/nuclei/dns.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/misconfiguration/ -o $domain/Recon/nuclei/misconfiguration.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/exposed-panels/ -o $domain/Recon/nuclei/panels.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/technologies/ -o $domain/Recon/nuclei/technologies.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/exposures/ -o $domain/Recon/nuclei/exposures.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/helpers/ -o $domain/Recon/nuclei/helpers.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/fuzzing/arbitrary-file-read.yaml -o $domain/Recon/nuclei/arbitrary-file-read.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/fuzzing/directory-traversal.yaml -o $domain/Recon/nuclei/directory-traversal.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/fuzzing/generic-lfi-fuzzing.yaml -o $domain/Recon/nuclei/generic-lfi-fuzzing.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/fuzzing/iis-shortname.yaml -o $domain/Recon/nuclei/iis-shortname.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/artica-web-proxy-workflow.yaml -o $domain/Recon/nuclei/artica-web-proxy-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/bigip-workflow.yaml -o $domain/Recon/nuclei/bigip-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/cisco-asa-workflow.yaml -o $domain/Recon/nuclei/cisco-asa-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/grafana-workflow.yaml -o $domain/Recon/nuclei/grafana-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/jira-workflow.yaml -o $domain/Recon/nuclei/jira-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/liferay-workflow.yaml -o $domain/Recon/nuclei/liferay-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/lotus-domino-workflow.yaml -o $domain/Recon/nuclei/lotus-domino-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/magmi-workflow.yaml -o $domain/Recon/nuclei/magmi-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/mida-eframework-workflow.yaml -o $domain/Recon/nuclei/mida-eframework-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/netsweeper-workflow.yaml -o $domain/Recon/nuclei/netsweeper-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/rabbitmq-workflow.yaml -o $domain/Recon/nuclei/rabbitmq-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/sap-netweaver-workflow.yaml -o $domain/Recon/nuclei/sap-netweaver-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/solarwinds-orion-workflow.yaml -o $domain/Recon/nuclei/solarwinds-orion-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/springboot-workflow.yaml -o $domain/Recon/nuclei/springboot-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/thinkphp-workflow.yaml -o $domain/Recon/nuclei/thinkphp-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/vbulletin-workflow.yaml -o $domain/Recon/nuclei/vbulletin-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/weblogic-workflow.yaml -o $domain/Recon/nuclei/weblogic-workflow.yaml.txt -v
	cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/workflows/wordpress-workflow.yaml -o $domain/Recon/nuclei/wordpress-workflow.yaml.txt -v
done
}
scanner
