#! /usr/bin/env python3
"""
Fetch script data by scraping blockchain.info.

Useful for debugging this package.
"""

import requests
import bs4
from argparse import ArgumentParser

from bitcoinscript.format import parse_formatted_script

###############################################################################

BASE_URL = 'https://blockchain.info'

###############################################################################

def make_url(k, v):
    return BASE_URL + ( '/%s/%s' % (k, v))

def fetch(url):
    if url.startswith('/'):
        url = BASE_URL + url
    url +=  '?show_adv=true'
    #print('Requesting: %s' % url)
    r = requests.get(url)
    return bs4.BeautifulSoup(r.text, "lxml")

def fetch_tx_page(txid):
    return fetch(make_url('tx', txid))

def extract_inscript(page, input_idx):
    inscript_root = [ e for e in page.find_all('h2') if 'Input Scripts' in e.text ][0]
    inscripts_table = inscript_root.parent.table
    s = inscripts_table.find_all('tr')[input_idx].td.text
    return clean_formatted_script(s)

def extract_outscript(page, output_idx):
    inscript_root = [ e for e in page.find_all('h2') if 'Output Scripts' in e.text ][0]
    inscripts_table = inscript_root.parent.table
    s = inscripts_table.find_all('tr')[output_idx].td.text
    return clean_formatted_script(s)

def extract_txindex(page, input_idx):
    input_elem = page.find(class_ = 'txdiv').table.find_all('tr')[1].find_all('td')[0]
    txindex_url = [ x.get('href') for x in input_elem.find_all('a') if '/tx-index/' in x.get('href') ][input_idx]
    paying_output_idx = int(txindex_url.split('/')[-1])
    return paying_output_idx, txindex_url

def clean_formatted_script(s):
    if 'Empty' in s:
        return ''
    s = s.splitlines()[0]
    for suffix in [ '(decoded)' ]:
        if s.endswith(suffix):
            s = s[:-len(suffix)]
    return s.strip()
        

###############################################################################
# MAIN

def main():
    
    options = getopt()
    txid = options.txid
    input_idx = options.input_idx

    page = fetch_tx_page(txid)
    inscript_formatted = extract_inscript(page, input_idx)
    inscript = parse_formatted_script(inscript_formatted).hex()
    paying_output_idx, txindex_url = extract_txindex(page, input_idx)
    
    page = fetch(txindex_url)
    outscript_formatted = extract_outscript(page, paying_output_idx)
    outscript = parse_formatted_script(outscript_formatted).hex()
    
    print('INPUT: txid=%s, idx=%s' % (txid, input_idx))
    print('Pubkey script (formatted):    %s' % outscript_formatted)
    print('Signature Script (formatted): %s' % inscript_formatted)
    print('Pubkey script:     %s' % outscript)
    print('Signature Script:  %s' % inscript)
    
    if options.snippet:
        print()
        print('#' + '-'*80)
        print('# SAMPLE CODE FOR TESTING:')
        print()
        print('from bitcoinscript import *')
        print('outscript = outscript_from_raw(bytes.fromhex("%s"))' % outscript)
        print('script_type = outscript.type')
        print('inscript = inscript_from_raw(bytes.fromhex("%s"), outscript)' % inscript)
        print()
    

###############################################################################

def getopt():
    parser = ArgumentParser()
    parser.add_argument('txid', help = 'TXID of the *spending* tx (containing the signature script)')
    parser.add_argument('input_idx', type = int, help = 'Index of the txinput to fetch')
    parser.add_argument('-x', '--snippet', action = 'store_true', help = 'Print code snippet to aid testing')
    return parser.parse_args()

###############################################################################

if __name__ == '__main__':
    main()
