# -*- coding: utf-8 -*-

import unittest, socket, logging, os
from ..util import TestClient, Msg

class TestChannel(TestClient, unittest.TestCase):
    user = b'foo'
    host = socket.gethostname().encode('latin-1')

    def openCircuit(self, auth=True):
        'Open TCP connection and sent auth info'
        self.connectTCP()
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
        ])
        if auth:
            self.sendTCP([
                Msg(cmd=20, body=self.user),
                Msg(cmd=21, body=self.host),
            ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12
        self.sver = rep.dcnt

    def test_echo(self):
        self.openCircuit()
        self.sendTCP([
            Msg(cmd=23, dtype=12, dcnt=23, p1=5678, p2=9101112),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=23)

    def test_channel_create(self):
        'Create and close a channel'
        self.openCircuit()
        cid, sid = 156, None

        self.sendTCP([
            Msg(cmd=18, p1=cid, p2=13, body=b'ival'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=22, p1=cid, p2=3)

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=18, dtype=5, dcnt=1, p1=cid)
        sid = rep.p2

        self.sendTCP([
            Msg(cmd=12, p1=sid, p2=cid),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=12, p1=sid, p2=cid)

    def test_channel_bad(self):
        'Attempt to open a channel to a non-existant PV'
        self.openCircuit()
        cid = 156

        self.sendTCP([
            Msg(cmd=18, p1=cid, p2=13, body=b'invalid'),
        ])

        rep = self.recvTCP()
        if self.sver>=6:
            self.assertCAEqual(rep, cmd=26, p1=cid)
        else:
            self.assertCAEqual(rep, cmd=11, p1=cid)

if __name__=='__main__':
    if 'LOGLEVEL' in os.environ:
        logging.basicConfig(level=logging.getLevelName(os.environ['LOGLEVEL']))
    unittest.main()
