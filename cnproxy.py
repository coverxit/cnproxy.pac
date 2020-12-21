#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib.request
import re, ast

PAC_PREFIX = '''const proxy = "SOCKS5 127.0.0.1:10808;SOCKS5 127.0.0.1:1080;";
const direct = "DIRECT;";

const hasOwnProperty = Object.hasOwnProperty;

const china_domains = {
'''

PAC_SUFFIX = '''
};

function is_china_domain(domain) {
  return !!dnsDomainIs(domain, ".cn") || !!dnsDomainIs(domain, '.xn--fiqs8s');
}

function match_domains(domain, domains) {
  let suffix;
  let pos = domain.lastIndexOf('.');
  pos = domain.lastIndexOf('.', pos - 1);
  while (1) {
    if (pos <= 0) {
      return hasOwnProperty.call(domains, domain);
    }
    suffix = domain.substring(pos + 1);
    if (hasOwnProperty.call(domains, suffix)) {
      return true;
    }
    pos = domain.lastIndexOf('.', pos - 1);
  }
}

function FindProxyForURL(url, host) {
  if (typeof host === 'undefined'
    || isPlainHostName(host) === true
    || host === '127.0.0.1'
    || host === 'localhost') {
    return direct;
  }

  if (is_china_domain(host) === true) {
    return proxy;
  }

  if (match_domains(host, china_domains) === true) {
    return proxy;
  }

  return direct;
}
'''

CONF_PREFIX = '''[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system, 114.114.114.114, 112.124.47.27, 8.8.8.8, 8.8.4.4

[Rule]
'''

CONF_SUFFIX = '''

DOMAIN-SUFFIX,cn,PROXY
DOMAIN-SUFFIX,xn--fiqs8s,PROXY
GEOIP,CN,PROXY

FINAL,DIRECT

[URL Rewrite]
^http://(www.)?google.cn https://www.google.com 302
'''

WHITELIST_PAC = 'https://raw.githubusercontent.com/MatcherAny/whitelist.pac/master/whitelist.pac'
SKIP_DOMAINS = [
  'adnxs.com', 
  'betrad.com',
  'imrworldwide.com',
  'scorecardresearch.com',
  'quantserve.com',

  'images-cn.ssl-images-amazon.com',
  'images-cn-4.ssl-images-amazon.com',
  'unagi-cn.amazon.com',

  'apple.com',
  'mzstatic.com',

  '2mdn.net',
  'doubleclick.com',
  'doubleclick.net', 
  'doubleclickbygoogle.com',

  'gravatar.com',

  'jsdelivr.net',

  'microsoft.com',

  'paypal.com'
]

request = urllib.request.urlopen(WHITELIST_PAC)
raw = request.read().decode('utf8').replace('\n', '')
raw = '{' + re.search(r'var white_domains = {(.*)};', raw).group(1) + '}'

obj = ast.literal_eval(raw)
domains = []
for tld in obj:
    for name in obj[tld]:
        full_domain = name + '.' + tld
        if name and not full_domain in SKIP_DOMAINS:
            domains.append(full_domain)
domains = sorted(domains)

with open('cnproxy.pac', 'w') as pac:
    pac.write(PAC_PREFIX)
    pac.write('  ' + ',\n  '.join(map(lambda d: '"{}": 1'.format(d), domains)))
    pac.write(PAC_SUFFIX)

with open('cnproxy.conf', 'w') as conf:
    conf.write(CONF_PREFIX)
    conf.write('\n'.join(map(lambda d: 'DOMAIN-SUFFIX,{},PROXY'.format(d), domains)))
    conf.write(CONF_SUFFIX)