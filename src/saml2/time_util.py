#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Google Inc.
# Copyright (C) 2009 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" 
Implements some usefull functions when dealing with validity of 
different types of information.
"""

import re
import time
from datetime import timedelta
from datetime import datetime

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIME_FORMAT_WITH_FRAGMENT = re.compile(
    "^(\d{4,4}-\d{2,2}-\d{2,2}T\d{2,2}:\d{2,2}:\d{2,2})\.\d*Z$")

# ---------------------------------------------------------------------------
#I'm sure this is implemeted somewhere else cann't find it now though, so I
#made an attempt.
#Implemented according to 
#http://www.w3.org/TR/2001/REC-xmlschema-2-20010502/
#adding-durations-to-dateTimes

def f_quotient(arg0, arg1, arg2=0):
    if arg2:
        return int((arg0-arg1)/(arg2-arg1))
    elif arg0 == 0:
        return 0
    else:
        return int(arg0/arg1)

def modulo(arg0, arg1, arg2=0):
    if arg2:
        return ((arg0 - arg1) % (arg2 - arg1)) + arg1
    else:
        return arg0 % arg1

DAYS_IN_MONTH = {
    1: 31,
    3: 31,
    4: 30,
    5: 31,
    6: 30,
    7: 31,
    8: 31,
    9: 30,
    10: 31,
    11: 30,
    12: 31,
    }
    
def days_in_february(year):
    if modulo(year, 400) == 0:
        return 29
    elif (modulo(year, 100) != 0) and (modulo(year, 4) == 0):
        return 29
    else:
        return 28

def maximum_day_in_month_for(year_value, month_value):
    month = modulo(month_value, 1, 13)
    year = year_value + f_quotient(month_value, 1, 13)
    try: 
        return DAYS_IN_MONTH[month]
    except KeyError:
        return days_in_february(year)
          
D_FORMAT = [
    ("Y", "tm_year"),
    ("M", "tm_mon"),
    ("D", "tm_mday"),
    ("T", None),
    ("H", "tm_hour"),
    ("M", "tm_min"),
    ("S", "tm_sec")
]

def parse_duration(duration):
    # (-)PnYnMnDTnHnMnS
    index = 0
    if duration[0] == '-':
        sign = '-'
        index += 1
    else:
        sign = '+'
    assert duration[index] == "P"
    index += 1
    
    dic = dict([(typ, 0) for (code, typ) in D_FORMAT])
    
    for code, typ in D_FORMAT:
        #print duration[index:], code
        if duration[index] == '-':
            raise Exception("Negation not allowed on individual items")
        if code == "T":
            if duration[index] == "T":
                index += 1
                if index == len(duration):
                    raise Exception("Not allowed to end with 'T'")
            else:
                raise Exception("Missing T")
        else:
            try:
                mod = duration[index:].index(code)
                try:
                    dic[typ] = int(duration[index:index+mod])
                except ValueError:
                    if code == "S":
                        try:
                            dic[typ] = float(duration[index:index+mod])
                        except ValueError:
                            raise Exception("Not a float")
                    else:
                        raise Exception(
                                "Fractions not allow on anything byt seconds")
                index = mod+index+1
            except ValueError:
                dic[typ] = 0

        if index == len(duration):
            break
        
    return (sign, dic)
    
def add_duration(tid, duration):
    
    (sign, dur) = parse_duration(duration)
    
    if sign == '+':
        #Months
        temp = tid.tm_mon + dur["tm_mon"]
        month = modulo(temp, 1, 13)
        carry = f_quotient(temp, 1, 13)
        #Years
        year = tid.tm_year + dur["tm_year"] + carry
        # seconds
        temp = tid.tm_sec + dur["tm_sec"]
        secs = modulo(temp, 60)
        carry = f_quotient(temp, 60)
        # minutes
        temp = tid.tm_min + dur["tm_min"] + carry
        minutes = modulo(temp, 60)
        carry = f_quotient(temp, 60)
        # hours
        temp = tid.tm_hour + dur["tm_hour"] + carry
        hour = modulo(temp, 60)
        carry = f_quotient(temp, 60)
        # days
        if dur["tm_mday"] > maximum_day_in_month_for(year, month):
            temp_days = maximum_day_in_month_for(year, month)
        elif dur["tm_mday"] < 1:
            temp_days = 1
        else:
            temp_days = dur["tm_mday"]
        days = temp_days + tid.tm_mday + carry
        while True:
            if days < 1:
                pass
            elif days > maximum_day_in_month_for(year, month):
                days = days - maximum_day_in_month_for(year, month)
                carry = 1
            else:
                break
            temp = month + carry
            month = modulo(temp, 1, 13)
            year = year + f_quotient(temp, 1, 13)
    
        return time.localtime(time.mktime((year, month, days, hour, minutes, 
                                secs, 0, 0, -1)))
    else:
        pass

# ---------------------------------------------------------------------------

def time_in_a_while(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0):
    """
    format of timedelta:
        timedelta([days[, seconds[, microseconds[, milliseconds[,
                    minutes[, hours[, weeks]]]]]]])
    """
    now = datetime.utcnow()
    delta = timedelta(*[days, seconds, microseconds, milliseconds, minutes,
                    hours, weeks])
    soon = now + delta
    return soon

def time_a_while_ago(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0):
    """
    format of timedelta:
        timedelta([days[, seconds[, microseconds[, milliseconds[,
                    minutes[, hours[, weeks]]]]]]])
    """
    now = datetime.utcnow()
    delta = timedelta(*[days, seconds, microseconds, milliseconds, minutes,
                    hours, weeks])
    prev = now - delta
    return prev

def in_a_while(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0, format=None):
    """
    format of timedelta:
        timedelta([days[, seconds[, microseconds[, milliseconds[,
                    minutes[, hours[, weeks]]]]]]])
    """
    if not format:
        format = TIME_FORMAT
    return time_in_a_while(days, seconds, microseconds, milliseconds,
                minutes, hours, weeks).strftime(format)

def a_while_ago(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0, format=None):
    if not format:
        format = TIME_FORMAT
    return time_a_while_ago(days, seconds, microseconds, milliseconds,
                minutes, hours, weeks).strftime(format)
                
# ---------------------------------------------------------------------------

def shift_time(dtime, shift):
    """ Adds/deletes an integer amount of seconds from a datetime specification
    
    :param dtime: The datatime specification
    :param shift: The wanted time shift (+/-)
    :return: A shifted datatime specification
    """
    tstruct = dtime.timetuple()
    tfl = time.mktime(tstruct)
    tfl += shift
    return datetime.utcfromtimestamp(tfl)
    
# ---------------------------------------------------------------------------

def str_to_time(timestr):
    if not timestr:
        return 0
    try:
        then = time.strptime(timestr, TIME_FORMAT)
    except Exception: # assume it's a format problem
        try:
            elem = TIME_FORMAT_WITH_FRAGMENT.match(timestr)
        except Exception, exc:
            print "Exception: %s on %s" % (exc, timestr)
            raise
        then = time.strptime(elem.groups()[0]+"Z", TIME_FORMAT)
        
    return then

def instant(format=None):
    if not format:
        format = TIME_FORMAT
    return datetime.utcnow().strftime(format)
    
# ---------------------------------------------------------------------------

def daylight_corrected_now():
    lgmt = list(time.gmtime())
    lgmt[8] = time.daylight
    return time.mktime(lgmt)    
    
# ---------------------------------------------------------------------------

def not_before(point):
    if not point:
        return True
        
    then = str_to_time(point)
    now = time.gmtime()

    if now > then:
        return True
    else:
        return False

def valid( valid_until ):
    """ Checks whether a valid_until specification is still valid
    :param valid_until: The string representation of a time
    :return: True if the time specified in valid_until is now or sometime 
        in the future. Otherwise False.
    """
    if not valid_until:
        return True
        
    then = str_to_time( valid_until )
    now = time.gmtime()
    
    if now <= then:
        return True
    else:
        return False

def later_than(then, that):
    then = str_to_time( then )
    that = str_to_time( that )
    
    return then >= that
    