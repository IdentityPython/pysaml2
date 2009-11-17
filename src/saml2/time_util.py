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
#http://www.w3.org/TR/2001/REC-xmlschema-2-20010502/#adding-durations-to-dateTimes

def f_quotient(a, b, c=0):
    if c:
        return int((a-b)/(c-b))
    elif a == 0:
        return 0
    else:
        return int(a/b)

def modulo(a, b, c=0):
    if c:
        return ((a - b)%(c - b)) + b
    else:
        return a%b

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
    
def days_in_february(y):
    if modulo(y, 400) == 0:
        return 29
    elif (modulo(y, 100) != 0) and (modulo(y, 4) == 0):
        return 29
    else:
        return 28

def maximum_day_in_month_for(yearValue, monthValue):
    m = modulo(monthValue, 1, 13)
    y = yearValue + f_quotient(monthValue, 1, 13)
    try: 
        return DAYS_IN_MONTH[m]
    except KeyError:
        return days_in_february(y)
          
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
    # PnYnMnDTnHnMnS
    assert duration[0] == "P"
    n = 1
    d = {}
    for code, typ in D_FORMAT:
        print duration[n:], code        
        if code == "T":
            if duration[n] == "T":
                n += 1
            else:
                raise Exception("Missing T")
        else:
            try:
                m = duration[n:].index(code)
                try:
                    d[typ] = int(duration[n:n+m])
                except ValueError:
                    d[typ] = float(duration[n:n+m])
                n = m+n+1
            except ValueError:
                d[typ] = 0
                pass
    
    return d
    
def add_duration(tid, duration):
    
    dur = parse_duration(duration)
        
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

# ---------------------------------------------------------------------------

def time_in_a_while(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0):
    """
    format of timedelta:
        timedelta([days[, seconds[, microseconds[, milliseconds[,
                    minutes[, hours[, weeks]]]]]]])
    """
    now = datetime.now()
    t = timedelta(*[days,seconds,microseconds,milliseconds,minutes,
                    hours,weeks])
    soon = now + t
    return soon

def in_a_while(days=0, seconds=0, microseconds=0, milliseconds=0,
                minutes=0, hours=0, weeks=0):
    """
    format of timedelta:
        timedelta([days[, seconds[, microseconds[, milliseconds[,
                    minutes[, hours[, weeks]]]]]]])
    """
    return time_in_a_while(days, seconds, microseconds, milliseconds,
                minutes, hours, weeks).strftime(TIME_FORMAT)

# ---------------------------------------------------------------------------

def str_to_time(timestr):
    if not timestr:
        return 0
    try:
        then = time.strptime(timestr, TIME_FORMAT)
    except Exception: # assume it's a format problem
        try:
            m = TIME_FORMAT_WITH_FRAGMENT.match(timestr)
        except Exception, e:
            print "Exception: %s on %s" % (e,timestr)
            raise
        then = time.strptime(m.groups()[0]+"Z", TIME_FORMAT)
        
    return then

def instant():
    return datetime.now().strftime(TIME_FORMAT)
    