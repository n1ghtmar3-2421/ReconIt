#!/bin/bash
host=$1
#echo "Enter ASN number :"
#read asn
#amass intel --asn $asn -o Results/asn.txt
domain_enum(){
for domain in $(cat $host);
do
	mkdir -p Results Results/Nuclei Results/Domains Results/urls Results/XSS
	subfinder -d $domain -o Results/Domains/subfinder.txt
	assetfinder -subs-only $domain | tee -a Results/Domains/domain.txt
	amass enum -passive -d $domain -o  Results/Domains/passive.txt-
	python3 crtfinder/crtfinder.py -u $domain | tee -a Results/Domains/crtfinder.txt
	./puredns/puredns bruteforce best-dns-wordlist.txt $domain -w Results/Domains/puredns.txt
	cat Results/Domains/*.txt | tee -a Results/tmp.txt
	rm Results/Domains/subfinder.txt
	rm Results/Domains/domain.txt
	rm Results/Domains/passive.txt
done
}
domain_enum
tmp_asd(){
	cat Results/tmp.txt | sort -u >> Results/all.txt
	rm Results/tmp.txt
}
tmp_asd
http_probe(){
	cat Results/all.txt | httprobe | tee -a Results/probed_domain.txt
}
http_probe
sub_takeover(){
	subzy -targets Results/all.txt | tee -a Results/takeover.txt
}
sub_takeover
urls(){
	cat Results/probed_domain.txt | waybackurls | tee Results/urls/wayback.txt
	cat Results/probed_domain.txt | gau | tee Results/urls/gau.txt
	cat Results/urls/* | sort -u | tee Results/urls/urls.txt
	rm Results/urls/wayback.txt
	rm Results/urls/gau.txt
}
urls
nuclei_check(){
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/cves/ -o Results/Nuclei/cves.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/default-logins/ -o Results/Nuclei/default_logins.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/exposed-panels/ -o Results/Nuclei/exposed_panels.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/exposed-tokens/ -o Results/Nuclei/exposed_tokens.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/exposures/ -o Results/Nuclei/exposures.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/fuzzing/ -o Results/Nuclei/fuzzing.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/headless/ -o Results/Nuclei/headless.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/helpers/ -o Results/Nuclei/helpers.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/iot/ -o Results/Nuclei/iot.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/miscellaneous/ -o Results/Nuclei/miscellaneous.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/misconfiguration/ -o Results/Nuclei/misconfiguration.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/network/ -o Results/Nuclei/network.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/takeovers/ -o Results/Nuclei/takeovers.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/technologies/ -o Results/Nuclei/technologies.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/vulnerabilities/ -o Results/Nuclei/vulnerabilities.txt
	cat Results/probed_domain.txt | nuclei -silent -t /root/nuclei-templates/workflows/ -o Results/Nuclei/workflows.txt
	cat Results/Nuclei/*.txt | sort -u >> Results/nuclei.txt
}
nuclei_check
