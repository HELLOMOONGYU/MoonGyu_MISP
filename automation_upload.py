#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from pymisp.api import PyMISP
import argparse
from pathlib import Path
import hashlib
import os

def calc_md5(file_name):
    with open(file_name, 'rb') as f:
        data = f.read()
        hash = hashlib.md5(data).hexdigest()
        return hash

def calc_sha1(file_name):
    with open(file_name, 'rb') as f:
        data = f.read()
        hash = hashlib.sha1(data).hexdigest()
        return hash

def calc_sha256(file_name):
    with open(file_name, 'rb') as f:
        data = f.read()
        hash = hashlib.sha256(data).hexdigest()
        return hash

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send malware sample to MISP.')
    parser.add_argument("-u", "--upload", type=str, required=True, help="File or directory of files to upload.")
    parser.add_argument("-d", "--distrib", type=int, help="The distribution setting used for the attributes and for the newly created event, if relevant. [0-3].")
    parser.add_argument("-c", "--comment", type=str, help="Comment for the uploaded file(s).")
    parser.add_argument('-m', '--is-malware', action='store_true', help='The file(s) to upload are malwares')
    parser.add_argument('--expand', action='store_true', help='(Only if the file is a malware) Run lief expansion (creates objects)')
    parser.add_argument("-e", "--event", type=int, default=None, help="Not supplying an event ID will cause MISP to create a single new event for all of the POSTed malware samples.")
    parser.add_argument("-l", "--last", type=int, default=None, help="last event id")
    args = parser.parse_args()

    misp_url = 'https://3.87.57.59/'
    misp_key = 'secrect'

    dir_path = args.upload
    target_files = []
    
    for (root, directories, files) in os.walk(dir_path):
        for d in directories:
            d_path = os.path.join(root, d)
        
        for file in files:
            file_path = os.path.join(root, file)
            target_files.append(file_path)



    files = []
    
    for file_path in target_files:
        
        misp = ExpandedPyMISP(misp_url, misp_key, False)
        p = Path(file_path)
        files = [p]
        md5_file_hash = calc_md5(file_path)
        sha1_file_hash = calc_sha1(file_path)
        sha256_file_hash = calc_sha256(file_path)

        with open('temp_hash.txt','w') as f:
            f.write(sha1_file_hash+'\n')
        
        if args.is_malware:
            arg_type = 'malware-sample'
        else:
            arg_type = 'attachment'

        # Create attributes
        attributes = []
        for f in files:
            a = MISPAttribute()
            a.type = arg_type
            a.value = f.name
            a.data = f
            a.comment = args.comment
            a.distribution = args.distrib
            if args.expand and arg_type == 'malware-sample':
                a.expand = 'binary'
            attributes.append(a)

        if args.event:
            for a in attributes:
                misp.add_attribute(args.event, a)
        else:
            m = MISPEvent()
            m.info = str(sha1_file_hash)
            m.distribution = args.distrib
            m.attributes = attributes
            if args.expand and arg_type == 'malware-sample':
                m.run_expansions()
            misp.add_event(m)
            
        with open('temp_hash.txt', 'r') as f:
            free_text_misp = PyMISP(misp_url, misp_key, False)
            args.last +=1 
            free_text_misp.freetext(args.last,f.read())
           
        