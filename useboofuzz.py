# coding: utf8

import boofuzz
import win32api
import win32con
from flask import Flask, make_response, request, render_template, json, redirect, url_for
from boofuzz import *
from boofuzz import fuzz_logger_csv
import sys
import subprocess

from test import Logger

'''
Modbus-TCP boofuzz python

'''
print(sys.argv[1],sys.argv[2])
ip = sys.argv[2]
port = sys.argv[3]


def ftp():
    """
        This example is a very simple FTP fuzzer. It uses no process monitory
        (procmon) and assumes that the FTP server is already running.
        """
    session = Session(target=Target(connection=TCPSocketConnection(str(ip),int(port))))

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    # s_initialize("pass")
    # s_string("PASS")
    # s_delim(" ")
    # s_string("james")
    # s_static("\r\n")
    #
    # s_initialize("stor")
    # s_string("STOR")
    # s_delim(" ")
    # s_string("AAAA")
    # s_static("\r\n")
    #
    # s_initialize("retr")
    # s_string("RETR")
    # s_delim(" ")
    # s_string("AAAA")
    # s_static("\r\n")

    session.connect(s_get("user"))
    # session.connect(s_get("user"), s_get("pass"))
    # session.connect(s_get("pass"), s_get("stor"))
    # session.connect(s_get("pass"), s_get("retr"))

    session.fuzz()

def http():
    session = Session(target=Target(connection=TCPSocketConnection(str(ip),int(port))), )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1")
        s_string("/index.html", name="Request-URI")
        s_delim(" ", name="space-2")
        s_string("HTTP/1.1", name="HTTP-Version")
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line")
        s_delim(" ", name="space-3")
        s_string("example.com", name="Host-Line-Value")
        s_static("\r\n", name="Host-Line-CRLF")
        s_static("Content-Length:", name="Content-Length-Header")
        s_delim(" ", name="space-4")
        s_size("Body-Content", output_format="ascii", name="Content-Length-Value")
        s_static("\r\n", "Content-Length-CRLF")
    s_static("\r\n", "Request-CRLF")

    with s_block("Body-Content"):
        s_string("Body content ...", name="Body-Content-Value")

    session.connect(s_get("Request"))

    session.fuzz()

def mdns():
    def insert_questions(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
        node.names["Questions"].value = 1 + node.names["queries"].current_reps
        node.names["Authority"].value = 1 + node.names["auth_nameservers"].current_reps

    s_initialize("query")
    s_word(0, name="TransactionID")
    s_word(0, name="Flags")
    s_word(1, name="Questions", endian=">")
    s_word(0, name="Answer", endian=">")
    s_word(1, name="Authority", endian=">")
    s_word(0, name="Additional", endian=">")

    # ######## Queries ################
    if s_block_start("query"):
        if s_block_start("name_chunk"):
            s_size("string", length=1)
            if s_block_start("string"):
                s_string("A" * 10)
            s_block_end()
        s_block_end()
        s_repeat("name_chunk", min_reps=2, max_reps=4, step=1, fuzzable=True, name="aName")

        s_group("end", values=["\x00", "\xc0\xb0"])  # very limited pointer fuzzing
        s_word(0xC, name="Type", endian=">")
        s_word(0x8001, name="Class", endian=">")
    s_block_end()
    s_repeat("query", 0, 1000, 40, name="queries")

    # ####### Authorities #############
    if s_block_start("auth_nameserver"):
        if s_block_start("name_chunk_auth"):
            s_size("string_auth", length=1)
            if s_block_start("string_auth"):
                s_string("A" * 10)
            s_block_end()
        s_block_end()
        s_repeat("name_chunk_auth", min_reps=2, max_reps=4, step=1, fuzzable=True, name="aName_auth")
        s_group("end_auth", values=["\x00", "\xc0\xb0"])  # very limited pointer fuzzing

        s_word(0xC, name="Type_auth", endian=">")
        s_word(0x8001, name="Class_auth", endian=">")
        s_dword(0x78, name="TTL_auth", endian=">")
        s_size("data_length", length=2, endian=">")
        if s_block_start("data_length"):
            s_binary("00 00 00 00 00 16 c0 b0")  # This should be fuzzed according to the type, but I'm too lazy atm
        s_block_end()
    s_block_end()
    s_repeat("auth_nameserver", 0, 1000, 40, name="auth_nameservers")

    s_word(0)

    sess = Session(target=Target(connection=UDPSocketConnection(str(ip),int(port))))
    sess.connect(s_get("query"), callback=insert_questions)

    sess.fuzz()

def tftp():
    # port = 69
    # host = "175.212.140.54"

    session = Session(target=Target(connection=UDPSocketConnection(str(ip),int(port)), ), )

    s_initialize("RRQ")
    s_static("\x00\x01")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("WRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("TRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_static("mail")
    s_static("\x00")

    session.connect(s_get("RRQ"))
    session.connect(s_get("WRQ"))
    session.connect(s_get("TRQ"))

    session.fuzz()


def modbus():
    # csv_log = open('fuzz_results.csv', 'wb')
    # my_logger = [FuzzLoggerCsv(file_handle=csv_log)]
    sys.stdout = Logger("log_file.txt")
    sess = Session(target=Target(connection=TCPSocketConnection(str(ip),int(port))),)
    s_initialize("modbus_read_coil_memory")
    if s_block_start("modbus_head"):
        s_word(0x0000,name='transId',fuzzable=False)
        s_word(0x0000,name='protoId',fuzzable=False)
        s_word(0x0006,endian='>',name='length',fuzzable=False)
        s_byte(0xff,name='unit Identifier',fuzzable=False)
        if s_block_start('modbus_read_coil_memory'):
            s_byte(1,name='funcCode read coil memory',fuzzable=False)
            s_word(0,name='start address',endian='>',fuzzable=False)
            s_word(0,name='quantity',endian='>',fuzzable=True)
            s_block_end()
    s_block_end()
    s_repeat("modbus_read_coil_memory",min_reps=0,max_reps=40,name='modbus_read_coil_memorys')
    sess.connect(sess.root,s_get('modbus_read_coil_memory'))
    sess.fuzz()










# ip = '50.77.76.116'
# port = 502
# modbus()
eval(sys.argv[1]+'()')
# win32api.keybd_event(13, 0, 0, 0)
# win32api.keybd_event(13, 0, win32con.KEYEVENTF_KEYUP, 0)
