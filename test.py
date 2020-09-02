from __future__ import print_function

import csv
import datetime
import sys


class Logger(object):
    def __init__(self, fileN="Default.log"):
        self.terminal = sys.stdout
        self.log = open(fileN, "w")

    def write(self, input_bytes):
        self.terminal.write(input_bytes)
        self.log.write(input_bytes)
        self.flush()  # 每次写入后刷新到文件中，防止程序意外结束

    def flush(self):
        self.log.flush()


