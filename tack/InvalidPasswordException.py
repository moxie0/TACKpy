# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

class InvalidPasswordException(Exception):
    def __init__(self, args):
        Exception.__init__(self, args)