#! /usr/bin/env python

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.
import sys
from tack.commands.BreakCommand import BreakCommand
from tack.commands.CertificateCommand import CertificateCommand
from tack.commands.GenerateKeyCommand import GenerateKeyCommand
from tack.commands.HelpCommand import HelpCommand
from tack.commands.SignCommand import SignCommand
from tack.commands.ViewCommand import ViewCommand
from tack.crypto.OpenSSL import openssl

openssl.initialize()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        HelpCommand.printGeneralUsage("Missing command")
    elif sys.argv[1] == "genkey"[:len(sys.argv[1])]:
        GenerateKeyCommand(sys.argv[2:]).execute()
    elif sys.argv[1] == "sign"[:len(sys.argv[1])]:
        SignCommand(sys.argv[2:]).execute()
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        BreakCommand(sys.argv[2:]).execute()
    elif sys.argv[1] == "tackcert"[:len(sys.argv[1])]:
        CertificateCommand(sys.argv[2:]).execute()
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        ViewCommand(sys.argv[2:]).execute()
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        HelpCommand(sys.argv[2:]).execute()
    else:
        HelpCommand.printGeneralUsage("Unknown command: %s" % sys.argv[1])
