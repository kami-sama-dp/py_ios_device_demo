import logging
import sys

gettrace = getattr(sys, 'gettrace', None)

if gettrace():
    logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname): %(message)s',
                        level=logging.DEBUG)
else:
    logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname): %(message)s',
                        level=logging.INFO)

PROGRAM_NAME = 'py_ios_device'
