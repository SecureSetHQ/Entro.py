#!/usr/bin/python

# Python script to manipulate passphrases to analyze entropy
# Author: Jacob Torrey <jacob@jacobtorrey.com>
# Date: 11/16/2015

import json
import math
import string
import hashlib
import random

class EntropyAnalyzer:
    '''Class to hold the functions needed to analyze entropy of given passphrase choices'''
    def __init__(self, dictfile):
        '''Initializes the dictionary with passed JSON file'''
        f = open(dictfile, 'r')
        self.dict = json.load(f)
        self.memoize = dict()

        self.filters = dict()
        self.filters['shorter_than_10'] = lambda x: len(x) < 10
        self.filters['shorter_than_8'] = lambda x: len(x) < 8
        self.filters['longer_than_3'] = lambda x: len(x) > 3
        self.filters['alpha_only'] = lambda x: x.isalpha()
        self.filters['ascii_only'] = lambda x: (ord(c) < 128 for c in x)
        
        f.close()

    def get_pos(self, word):
        '''Return a list of parts-of-speech in the definition of the passed word'''
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
            self.memoize = dict()
        else:
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
        pos_count['any'] = len(sdict)
        return pos_count
    
    def calculate_security(self, pos_mask):
        '''Calulates the number of possibilities to guess to find the passphrase matching the part-of-speech mask'''
        pos_count = self.get_num_pos()
        pos_mask = self.parse_pos_mask(pos_mask)
        possibilities = 1
        for pos in pos_mask:
            possibilities *= pos_count[pos]
        hours = possibilities / 70000000.0 / (60 * 60)
        days = hours / 24.0
        print "Computed %d or approximately 2^%.4f bits of entropy\n" % (possibilities, self.poss_to_bits(possibilities))
        print "Time to crack: %.2f hrs (%.2f days) @ 70 M h/s" % (hours, days)
        return possibilities

    def poss_to_bits(self, poss):
        '''Converts a number of possibilities to approx. bits of entropy'''
        return math.log(poss)/math.log(2.0)

    def parse_pos_mask(self, pos_mask):
        '''Parse a part-of-speech mask'''
        split = string.split(pos_mask)
        return split

    def get_all_pos(self, pos):
        poses = []
        for w in self.dict:
            if pos in self.get_pos(w):
                poses.append(w)
        return poses

    def gen_pass(self, pos_mask):
        '''Generates a random passphrase from a given mask'''
        mask = self.parse_pos_mask(pos_mask)
        pw = ""
        for pos in mask:
            if pos == 'any':
                pw += random.choice(self.dict.keys())
            else:
                if pos not in self.memoize.keys():
                    self.memoize[pos] = self.get_all_pos(pos)
                pw += random.choice(self.memoize[pos])
        return pw

    def rand_crack(self, sha1sum, pos_mask):
        '''Attempts to randomly find a collision with the passed hash'''
        guess = self.gen_pass(pos_mask)
        while hashlib.sha1(guess).hexdigest() != sha1sum:
            guess = self.gen_pass(pos_mask)
        return guess

        
