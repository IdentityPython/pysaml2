#!/usr/bin/env python

import time
from saml2.time_util import f_quotient, modulo, parse_duration, add_duration
from saml2.time_util import str_to_time, instant, valid, in_a_while

def test_f_quotient():
    assert f_quotient(-1,3) == -1
    assert f_quotient(0,3) == 0
    assert f_quotient(1,3) == 0
    assert f_quotient(2,3) == 0
    assert f_quotient(3,3) == 1
    assert f_quotient(3.123,3) == 1

def test_modulo():
    assert modulo(-1,3) == 2
    assert modulo(0,3) == 0
    assert modulo(1,3) == 1
    assert modulo(2,3) == 2
    assert modulo(3,3) == 0
    x = 3.123
    assert modulo(3.123,3) == x - 3

def test_f_quotient_2():
    assert f_quotient(0, 1, 13) == -1
    for i in range(1,13):
        assert f_quotient(i, 1, 13) == 0
    assert f_quotient(13, 1, 13) == 1
    assert f_quotient(13.123, 1, 13) == 1

def test_modulo_2():
    assert modulo(0, 1, 13) == 12
    for i in range(1,13):
        assert modulo(i, 1, 13) == i
    assert modulo(13, 1, 13) == 1
    #x = 0.123
    #assert modulo(13+x, 1, 13) == 1+x

def test_parse_duration():
    (sign, d) = parse_duration("P1Y3M5DT7H10M3.3S")
    assert sign == "+"
    assert d['tm_sec'] == 3.3
    assert d['tm_mon'] == 3
    assert d['tm_hour'] == 7
    assert d['tm_mday'] == 5
    assert d['tm_year'] == 1
    assert d['tm_min'] == 10
    
def test_add_duration_1():
    #2000-01-12T12:13:14Z	P1Y3M5DT7H10M3S	2001-04-17T19:23:17Z    
    t = add_duration(str_to_time("2000-01-12T12:13:14Z"), "P1Y3M5DT7H10M3S")
    assert t.tm_year == 2001
    assert t.tm_mon == 4
    assert t.tm_mday == 17
    assert t.tm_hour == 19
    assert t.tm_min == 23
    assert t.tm_sec == 17
    
def test_add_duration_2():
    #2000-01-12 PT33H   2000-01-13
    t = add_duration(str_to_time("2000-01-12T00:00:00Z"),"PT33H")
    assert t.tm_year == 2000
    assert t.tm_mon == 1
    assert t.tm_mday == 14
    assert t.tm_hour == 9
    assert t.tm_min == 0
    assert t.tm_sec == 0
    
def test_str_to_time():
    t = time.mktime(str_to_time("2000-01-12T00:00:00Z"))
    assert t == 947631600.0
    
def test_instant():
    inst = str_to_time(instant())
    print inst
    now = time.gmtime()
    print now
    
    assert now >= inst
    
def test_valid():
    assert valid("2000-01-12T00:00:00Z") == False
    assert valid("2011-01-12T00:00:00Z") == True
    this_instance = instant()
    print this_instance
    assert valid(this_instance) == False # unless on a very fast machine :-)
    soon = in_a_while(seconds=10)
    assert valid(soon) == True
    
def test_timeout():
    soon = in_a_while(seconds=1)
    time.sleep(2)
    assert valid(soon) == False
