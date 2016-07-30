# -*- coding: utf-8 -*-

import unittest, socket, logging, os
from ..util import TestClient, Msg

class TestEcho(TestClient, unittest.TestCase):
    def test_echo(self):
        'Check that UDP echo request is ignored'
        self.sendUDP([
            Msg(cmd=23, dtype=12, dcnt=23, p1=5678, p2=9101112),
        ])
        self.assertRaises(socket.timeout, self.recvUDP)
        #rep, src = self.recvUDP()
        #self.assertCAEqual(rep[0], cmd=23, dtype=12, dcnt=23, p1=5678, p2=9101112)

class TestSearchUDP(TestClient, unittest.TestCase):

    def test_udplookup(self):
        'UDP name search as v13 client'
        searchid = 0x12345678
        self.sendUDP([
            Msg(cmd=0, dcnt=13),
            Msg(cmd=6, body='ival', dtype=5, dcnt=13, p1=searchid, p2=searchid),
        ])

        rep = self.recvUDP()

        self.assertCAEqual(rep[0], cmd=0)
        self.assertGreater(rep[0].dcnt, 6) # server version must be post Base 3.12

        self.assertCAEqual(rep[1], cmd=6, dtype=self.testport, dcnt=0, p2=searchid)
        # UDP search is supposed to include the version in the reply
        # but RSRV doesn't set this
        self.assertGreaterEqual(rep[1].size, 2)
        self.assertTrue(rep[1].p1==0xffffffff or rep[1].p1==0x7f000001,
                        "P1 unknown %08x"%rep[1].p1)

    def test_udplookup_err1(self):
        'UDP lookup of non-existant'
        searchid = 0x12345678
        self.sendUDP([
            Msg(cmd=0, dcnt=13),
            Msg(cmd=6, body='invalid', dtype=5, dcnt=13, p1=searchid, p2=searchid),
        ])

        self.assertRaises(socket.timeout, self.recvUDP)

    def test_udplookup_err2(self):
        '''UDP lookup of non-existant
        Request reply on failure, which should be ignored by the server
        '''
        searchid = 0x12345678
        self.sendUDP([
            Msg(cmd=0, dcnt=13),
            Msg(cmd=6, body='invalid', dtype=10, dcnt=13, p1=searchid, p2=searchid),
        ])

        self.assertRaises(socket.timeout, self.recvUDP)

class TestSearchTCP(TestClient, unittest.TestCase):
    def test_tcplookup(self):
        'TCP name search as v13 client'
        self.connectTCP()
        # server will wait for us to send version first

        searchid = 0x12345678
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12

        if rep.dcnt<12:
            self.skipTest("Server doesn't support TCP lookup")

        self.sendTCP([
            Msg(cmd=6, body='ival', dtype=5, dcnt=13, p1=searchid, p2=searchid),
        ])

        rep = self.recvTCP()

        self.assertCAEqual(rep, cmd=6, dtype=self.testport, dcnt=0, p2=searchid)
        # TCP search reply doesn't include a version number in the payload
        self.assertTrue(rep.p1==0xffffffff or rep.p1==0x7f000001,
                        "P1 unknown %08x"%rep.p1)

    def test_tcplookup_err1(self):
        'TCP lookup of non-existant w/o reply'
        self.connectTCP()
        # server will wait for us to send version first

        searchid = 0x12345678
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12

        if rep.dcnt<12:
            self.skipTest("Server doesn't support TCP lookup")

        self.sendTCP([
            Msg(cmd=6, body='invalid', dtype=5, dcnt=rep.dcnt, p1=searchid, p2=searchid),
        ])

        self.assertRaises(socket.timeout, self.recvTCP)

    def test_tcplookup_err2(self):
        'TCP lookup of non-existant w/ reply'
        self.connectTCP()
        # server will wait for us to send version first

        searchid = 0x12345678
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12

        if rep.dcnt<12:
            self.skipTest("Server doesn't support TCP lookup")

        self.sendTCP([
            Msg(cmd=6, body='invalid', dtype=10, dcnt=13, p1=searchid, p2=searchid),
        ])

        rep = self.recvTCP()

        self.assertCAEqual(rep, cmd=14, dtype=10, dcnt=13, p1=searchid, p2=searchid)

    def test_tcplookup_old(self):
        '''TCP name search as v11 client
        Strictly speaking this shouldn't work, though it doesn't matter so much
        as v11 clients won't make these requests
        '''
        self.connectTCP()
        # server will wait for us to send version first

        searchid = 0x12345678
        self.sendTCP([
            Msg(cmd=0, dcnt=11),
            Msg(cmd=6, body='ival', dtype=5, dcnt=11, p1=searchid, p2=searchid),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12

        if rep.dcnt<12:
            self.skipTest("Server doesn't support TCP lookup")

        self.sendTCP([
            Msg(cmd=6, body='ival', dtype=5, dcnt=13, p1=searchid, p2=searchid),
        ])

        rep = self.recvTCP()

        self.assertCAEqual(rep, cmd=6, dtype=self.testport, dcnt=0, p2=searchid)
        # TCP search reply doesn't include a version number in the payload
        self.assertTrue(rep.p1==0xffffffff or rep.p1==0x7f000001,
                        "P1 unknown %08x"%rep.p1)

if __name__=='__main__':
    if 'LOGLEVEL' in os.environ:
        logging.basicConfig(level=logging.getLevelName(os.environ['LOGLEVEL']))
    unittest.main()
