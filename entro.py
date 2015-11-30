#!/usr/bin/python

# Python script to manipulate passphrases to analyze entropy
# Author: Jacob Torrey <jacob@jacobtorrey.com>
# Date: 11/16/2015

import json
import math
import string
import itertools
import hashlib
import random
import time

class EntropyBase(object):
    '''Base class to hold shared functionality between the derived classes'''
    def __init__(self):
        self.memoize = dict()
        self.dict = dict()

    def poss_to_bits(self, poss):
        '''Converts a number of possibilities to approx. bits of entropy'''
        return math.log(poss)/math.log(2.0)

    def parse_mask(self, mask):
        '''Parse a pattern mask'''
        split = string.split(mask)
        return split

    def calculate_security(self, possibilities):
        '''Calulates the entropy and time to crack n possibilities'''
        hours = possibilities / 70000000.0 / (60 * 60)
        days = hours / 24.0
        print "Computed %d or approximately 2^%.4f bits of entropy\n" % (possibilities, self.poss_to_bits(possibilities))
        print "Time to crack: %.2f hrs (%.2f days) @ 70 M h/s\n" % (hours, days)
        return possibilities

    def iter_crack(self, sha1sum, pos_mask, timeout, timef = True):
        '''Attempts to crack a sha1sum via iterating through dictionary'''
        try:
            start = time.time()
            crack_count = 0
            mask = self.parse_mask(pos_mask)
            lol = []
            for pos in mask:
                if pos not in self.memoize.keys():
                    self.memoize[pos] = self.get_all_pos(pos)
                lol.append(self.memoize[pos])
            for perm in itertools.product(*lol):
                if timeout != 0 and (time.time() - start) >= timeout:
                    return crack_count
                teststr = ''.join(map(str, perm))
                if type(sha1sum) is set:
                    if hashlib.sha1(teststr).hexdigest() in sha1sum:
                        crack_count += 1
                else:
                    if sha1sum == hashlib.sha1(teststr).hexdigest():
                        crack_count += 1
                        if timef:
                            print "Took %d seconds to crack\n" % (time.time() - start)
                        return teststr
            return crack_count
        except KeyboardInterrupt:
            if timef:
                print "Cracked %d passwords in %d seconds\n" % (crack_count, (time.time() - start))
            return crack_count

    def gen_pass(self, mask):
        '''Generates a random passphrase from a given mask'''
        mask = self.parse_mask(mask)
        pw = ""
        for pos in mask:
            if pos not in self.memoize.keys():
                self.memoize[pos] = self.get_all_pos(pos)
            pw += random.choice(self.memoize[pos])
        return pw

#    def rand_crack(self, sha1sum, mask, timef = True):
#        '''Attempts to randomly find a collision with the passed hash'''
#        if timef:
#            start = time.time()
#        guess = self.gen_pass(mask)
#        while hashlib.sha1(guess).hexdigest() != sha1sum:
#            guess = self.gen_pass(mask)
#        if timef:
#            print "Took %d seconds to crack\n" % (time.time() - start)
#        return guess

    def load_hashes(self, filename):
        '''Loads in a JSON list of hashes to crack'''
        with open(filename, 'r') as f:
            hashes = json.load(f)
        return set(hashes)

class EntropyAnalyzer(EntropyBase):
    '''Class to hold the functions needed to analyze entropy of given passphrase choices'''
    def __init__(self, dictfile):
        '''Initializes the dictionary with passed JSON file'''
        super(EntropyAnalyzer, self).__init__()
        f = open(dictfile, 'r')
        self.dict = json.load(f)
        self.memoize = dict()

        self.filters = dict()
        self.filters['shorter_than_10'] = lambda x: len(x) < 10
        self.filters['shorter_than_8'] = lambda x: len(x) < 8
        self.filters['longer_than_3'] = lambda x: len(x) > 3
        self.filters['alpha_only'] = lambda x: x.isalpha()
        self.filters['ascii_only'] = lambda x: all(ord(c) < 128 for c in x)
        
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
        pos_mask = self.parse_mask(pos_mask)
        possibilities = 1
        for pos in pos_mask:
            possibilities *= pos_count[pos]
        return super(EntropyAnalyzer, self).calculate_security(possibilities)

    def get_all_pos(self, pos):
        poses = []
        for w in self.dict:
            if pos == "any" or pos in self.get_pos(w):
                poses.append(w)
        return poses

class PasswordPattern(EntropyBase):
    '''Class to show password patterns'''
    def __init__(self):
        '''Constructor for the password pattern class'''
        super(PasswordPattern, self).__init__()
        self.memoize['lower'] = list(string.ascii_lowercase)
        self.memoize['upper'] = list(string.ascii_uppercase)
        self.memoize['punc'] = list(string.punctuation)
        self.memoize['digit'] = list(string.digits)
        self.memoize['letter'] = list(string.ascii_letters)
        self.memoize['any'] = self.memoize['punc'] + self.memoize['digit'] + self.memoize['letter']

    def calculate_security(self, mask):
        '''Calulates the number of possibilities to guess to find the passphrase matching the part-of-speech mask'''
        mask = self.parse_mask(mask)
        possibilities = 1
        for e in mask:
            possibilities *= len(self.memoize[e])
        return super(PasswordPattern, self).calculate_security(possibilities)
