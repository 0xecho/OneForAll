#!/usr/bin/python3
# coding=utf-8

"""
OneForAll subdomain takeover module

:copyright: Copyright (c) 2019, Jing Ling. All rights reserved.
:license: GNU General Public License v3.0, see LICENSE for more details.
"""
import time
import json
from threading import Thread
from queue import Queue

import fire
from common.tablib.tablib import Dataset
from tqdm import tqdm

from config.log import logger
from config import settings
from common import utils
from common.module import Module

import dns.query
import dns.resolver
from dns.exception import DNSException

def query_authoritative_ns (domain, log=lambda msg: None):
    try:
        default = dns.resolver.get_default_resolver()
        ns = default.nameservers[0]

        n = domain.split('.')
        results = []

        for i in range(len(n), 0, -1):
            sub = '.'.join(n[i-1:])

            log('Looking up %s on %s' % (sub, ns))
            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, ns)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    raise Exception('%s does not exist.' % (sub))
                else:
                    raise Exception('Error %s' % (dns.rcode.to_text(rcode)))

            if len(response.authority) > 0:
                rrsets = response.authority
            elif len(response.additional) > 0:
                rrsets = [response.additional]
            else:
                rrsets = response.answer

            # Handle all RRsets, not just the first one
            for rrset in rrsets:
                for rr in rrset:
                    try:
                        print(rr.items)
                    except:
                        continue
                    if rr.rdtype == dns.rdatatype.SOA:
                        log('Same server is authoritative for %s' % (sub))
                    elif rr.rdtype == dns.rdatatype.A:
                        ns = rr.items[0].address
                        log('Glue record for %s: %s' % (rr.name, ns))
                    elif rr.rdtype == dns.rdatatype.NS:
                        authority = rr.target
                        ns = default.query(authority).rrset[0].to_text()
                        log('%s [%s] is authoritative for %s; ttl %i' % 
                            (authority, ns, sub, rrset.ttl))
                        if sub == domain:
                            results.append(authority.to_text()[:-1])
                    else:
                        # IPv6 glue records etc
                        #log('Ignoring %s' % (rr))
                        pass
    except:
        results = []

    return results


def get_fingerprint():
    path = settings.data_storage_dir.joinpath('fingerprints.json')
    with open(path, encoding='utf-8', errors='ignore') as file:
        fingerprints = json.load(file)
    return fingerprints

def get_expired_fingerprints():
    path = settings.data_storage_dir.joinpath('expired.json')
    with open(path, encoding='utf-8', errors='ignore') as file:
        fingerprints = json.load(file)
    return fingerprints

def get_cname(subdomain):
    resolver = utils.dns_resolver()
    try:
        answers = resolver.query(subdomain, 'CNAME')
    except Exception as e:
        logger.log('TRACE', e.args)
        return None
    for answer in answers:
        return answer.to_text()[:-1] if answer.to_text()[-1]=='.' else answer.to_text()  # 一个子域只有一个CNAME记录


class Takeover(Module):
    """
    OneForAll subdomain takeover module

    Example:
        python3 takeover.py --target www.example.com  --format csv run
        python3 takeover.py --targets ./subdomains.txt --thread 10 run

    Note:
        --format rst/csv/tsv/json/yaml/html/jira/xls/xlsx/dbf/latex/ods (result format)
        --path   Result directory (default directory is ./results)

    :param str target:   One domain (target or targets must be provided)
    :param str targets:  File path of one domain per line
    :param int thread:   threads number (default 20)
    :param str format:   Result format (default csv)
    :param str path:     Result directory (default None)
    """

    def __init__(self, target=None, targets=None, thread=20, path=None, format='csv'):
        Module.__init__(self)
        self.subdomains = set()
        self.module = 'Check'
        self.source = 'Takeover'
        self.target = target
        self.targets = targets
        self.thread = thread
        self.path = path
        self.format = format
        self.fingerprints = None
        self.subdomainq = Queue()
        self.cnames = list()
        self.results = Dataset()

    def save(self):
        logger.log('DEBUG', 'Saving results')
        if self.format == 'txt':
            data = str(self.results)
        else:
            data = self.results.export(self.format)
        utils.save_data(self.path, data)

    def compare(self, subdomain, cname, responses):
        domain_resp = self.get('http://' + subdomain, check=False, ignore=True)
        cname_resp = self.get('http://' + cname, check=False, ignore=True)
        if domain_resp is None or cname_resp is None:
            return

        for resp in responses:
            if resp in domain_resp.text and resp in cname_resp.text:
                logger.log('ALERT', f'{subdomain} takeover threat found')
                self.results.append([subdomain, cname])
                break

    def is_expired_or_nonexistant(self,subdomain,cname=False,ns=False):
        resp = self.get('http://' + subdomain, check=False, ignore=True)
        
        if resp is None:
            resolver = utils.dns_resolver()
            try:
                answers = resolver.query(subdomain, 'A')
            except Exception as e:
                if cname: 
                    logger.log('ALERT', f'Possible nonexistant domain threat found @ {subdomain}')
                    self.results.append([subdomain, "**non-Existant-domain**"])
                if ns:
                    logger.log('ALERT', f'Possible nonexistant Name server threat found @ {subdomain}')
                    self.results.append([subdomain, "**non-Existant-ns**"])
        elif resp:
            for fingerprint in self.fingerprints:
                for response in fingerprint.get('response'):
                    if response in resp.text:
                        logger.log('ALERT', f'Possible expired domain threat found @ {subdomain}')
                        self.results.append([subdomain, "**Expired**"])
                        break                

    def worker(self, subdomain):
        authoritative_ns = query_authoritative_ns(subdomain)
        cname = get_cname(subdomain)
        if cname is not None:
            main_domain = utils.get_main_domain(cname)
            for fingerprint in self.fingerprints:
                cnames = fingerprint.get('cname')
                if main_domain not in cnames:
                    continue
                responses = fingerprint.get('response')
                self.compare(subdomain, cname, responses)
            self.is_expired_or_nonexistant(cname, False)
        else:
            # MUST BE ROOT DOMAIN TO QUALIFY HERE
            if subdomain == utils.get_main_domain(subdomain):
                self.is_expired_or_nonexistant(subdomain, True)
        for ns in authoritative_ns:
            self.is_expired_or_nonexistant(ns, ns=True)

    def check(self):
        while not self.subdomainq.empty():  # 保证域名队列遍历结束后能退出线程
            subdomain = self.subdomainq.get()  # 从队列中获取域名
            self.worker(subdomain)
            self.subdomainq.task_done()

    def progress(self):
        bar = tqdm()
        bar.total = len(self.subdomains)
        bar.desc = 'Check Progress'
        bar.ncols = 80
        while True:
            done = bar.total - self.subdomainq.qsize()
            bar.n = done
            bar.update()
            if done == bar.total:  # 完成队列中所有子域的检查退出
                break

    def run(self):
        start = time.time()
        logger.log('INFOR', f'Start running {self.source} module')
        if isinstance(self.targets, set):
            self.subdomains = self.targets
        else:
            self.subdomains = utils.get_domains(self.target, self.targets)
        self.format = utils.check_format(self.format, len(self.subdomains))
        timestamp = utils.get_timestamp()
        name = f'takeover_check_result_{timestamp}'
        self.path = utils.check_path(self.path, name, self.format)
        if self.subdomains:
            logger.log('INFOR', f'Checking subdomain takeover')
            self.fingerprints = get_fingerprint()
            self.results.headers = ['subdomain', 'cname']
            # 创建待检查的子域队列
            for domain in self.subdomains:
                self.subdomainq.put(domain)
            # 进度线程
            progress_thread = Thread(target=self.progress, name='ProgressThread',
                                     daemon=True)
            progress_thread.start()
            # 检查线程
            for i in range(self.thread):
                check_thread = Thread(target=self.check, name=f'CheckThread{i}',
                                      daemon=True)
                check_thread.start()

            self.subdomainq.join()
            self.save()
        else:
            logger.log('FATAL', f'Failed to obtain domain')
        end = time.time()
        elapse = round(end - start, 1)
        logger.log('ALERT', f'{self.source} module takes {elapse} seconds, '
                            f'There are {len(self.results)} subdomains exists takeover')
        logger.log('INFOR', f'Subdomain takeover results: {self.path}')
        logger.log('INFOR', f'Finished {self.source} module')


if __name__ == '__main__':
    fire.Fire(Takeover)
