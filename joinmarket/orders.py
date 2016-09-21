#! /usr/bin/env python
from __future__ import absolute_import, print_function

import base64
import pprint
import sys
import abc
from protocol import offertypes

from joinmarket.enc_wrapper import init_keypair, as_init_encryption, init_pubkey, \
     NaclError
from joinmarket.support import get_log

log = get_log()

class OfferFieldError(Exception):
    pass

class OfferField(object):
    def __init__(self, name, ftype, val):
        self.name = name
        self.ftype = ftype
        self._val = self.sanitize(val)
    
    def sanitize(self, val):
        print("Here sanitize field value")
        if type(val) != self.ftype:
            raise OfferFieldError("Value: " + str(val) + " is not: " + str(ftype))
        #TODO stuff depending on type
        return val

    def set(self, val):
        self._val = self.sanitize(val)
        
    def get(self):
        return self._val
    
    def __str__(self):
        return self.name + ":"+str(val)

class Offer(object):
    
    def __init__(self, offertype, values):
        self.offertype = offertype
        assert self.offertype in offertypes
        self.fields = []
        for i, v in enumerate(values):
            self.fields.append(OfferField(offertypes[offertype][i][1],
                                          offertypes[offertype][i][0],
                                          v))
        assert self.check_fields()

    def check_fields(self):
        """Check that each field in the list of given
        fields matches the types required for this
        offer type. Return True/False"""        
        if not self.offertype in offertypes:
            return False
        expected_types = offertypes[self.offertype]
        if len(self.fields) != len(expected_types):
            return False
        for f, e in zip(self.fields, expected_types):
            if not isinstance(f, OfferField):
                return False
            if f.ftype != e:
                return False
        return True
    
    def get_fields(self):
        """Returns the set of fields in the offer
        as a list"""
        return [f.get() for f in fields]

    
            
            