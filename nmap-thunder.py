import argparse
from os import system as run

# list of powerful nmap commands to include

new_line = "="*20

def nmap_thunder(t):
	run("nmap --script=smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,mysql-vuln-cve2012-2122,http-litespeed-sourcecode-download,http-git,http-gitweb-projects-enum,http-malware-host,http-csrf,http-auth,http-security-headers,http-robots.txt,http-shellshock,ssl-heartbleed,ip-geolocation-geoplugin,ip-forwarding,http-rfi-spider,http-phpmyadmin-dir-traversal,http-php-version,traceroute-geolocation,hostmap-bfk,nmap-vulners,vulscan,http-enum,whois-domain,banner,http-sitemap-generator,dns-brute,http-waf-fingerprint,http-waf-detect,http-cors,http-cross-domain-policy,http-stored-xss,http-phpself-xss,http-dombased-xss,http-unsafe-output-escaping,http-vuln-cve2013-6786,http-xssed,http-sql-injection,http-vuln-cve2017-8917,firewalk,mysql-info,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3192,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-1001000,http-vuln-cve2017-5638,http-vuln-cve2017-5689,http-vuln-cve2017-8917 {}".format(t))


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--target", "-t", type=str, required=True)
	args = parser.parse_args()

	if args.target:
		nmap_thunder(args.target)

main()