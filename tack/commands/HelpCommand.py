import sys
from tack.commands.CertificateCommand import CertificateCommand
from tack.version import __version__
from tack.commands.BreakCommand import BreakCommand
from tack.commands.Command import Command
from tack.commands.GenerateKeyCommand import GenerateKeyCommand
from tack.commands.SignCommand import SignCommand
from tack.commands.ViewCommand import ViewCommand

class HelpCommand(Command):

    COMMANDS = {"genkey" : GenerateKeyCommand, "sign" : SignCommand,
                "break" : BreakCommand, "view" : ViewCommand,
                "tackcert" : CertificateCommand}

    def __init__(self, argv):
        Command.__init__(self, argv, "", "")

        if len(argv) < 1:
            HelpCommand.printGeneralUsage()

        self.command = argv[0]

        if not self.command in HelpCommand.COMMANDS:
            self.printError("%s not a valid command." % self.command)

    def execute(self):
        HelpCommand.COMMANDS[self.command].printHelp()

    @staticmethod
    def printHelp():
        print(\
"""Provides help for individual commands.

help <command>
""")

    @staticmethod
    def printGeneralUsage(message=None):
        print "Error: %s" % message
        print(\
"""\ntack.py version %s

Commands (use "help <command>" to see optional args):
  genkey
  sign     -k KEY -c CERT
  break    -k KEY
  view     FILE
  help     COMMAND
""" % __version__)
        sys.exit(-1)
