#!/usr/bin/python

# Python script to manipulate passphrases to analyze entropy
# Author: Jacob Torrey <jacob@jacobtorrey.com>
# Date: 11/16/2015

import json
import random

class EntropyAnalyzer:
    '''Class to hold the functions needed to analyze entropy of given passphrase choices'''
    def __init__(self, dictfile):
        f = open(dictfile, 'r')
        self.dict = json.load(f)
#        self.pos_count = self.get_num_pos()
        f.close()

    def get_pos(self, word):
        wobj = self.dict[word]
        poses = []
        for defi in wobj['definitions']:
            if not defi['part_of_speech'] in poses:
                poses.append(defi['part_of_speech'])
        return poses

    def filter_dict(self, filter_func, cull = False):
        '''Filters the dictionary based on passed filtering function on the word'''
        fdict = dict()
        for key, val in self.dict.items():
            if filter_func(key):
                fdict[key] = val
        if cull:
            self.dict = fdict
        return fdict

    def get_num_pos(self, sdict = None):
        '''Determines the count of each part of speech in the dictionary'''
        if sdict is None:
            sdict = self.dict
        pos_count = {'noun': 0, 'verb': 0, 'adverb': 0, 'adjective': 0, 'pronoun': 0, 'conjunction': 0, 'preposition': 0, 'interjection': 0}
        for key, val in sdict.items():
            for pos in self.get_pos(key):
                if pos in pos_count:
                    pos_count[pos] += 1
        return pos_count
    
