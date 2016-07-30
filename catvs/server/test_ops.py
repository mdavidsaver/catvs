# -*- coding: utf-8 -*-

import unittest, socket, logging
from ..util import TestClient, Msg

class TestOp(TestClient, unittest.TestCase):

    user = 'foo'
    host = socket.gethostname()

    def openChan(self):
        'Open TCP connection and create channel'
        self.cid = 156
        self.connectTCP()
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
            Msg(cmd=20, body=self.user),
            Msg(cmd=21, body=self.host),
            Msg(cmd=18, p1=self.cid, p2=13, body='ival'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12
        self.sver = rep.dcnt

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=22, p1=self.cid, p2=3)

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=18, dtype=5, dcnt=1, p1=self.cid)
        self.sid = rep.p2
        
        self.addCleanup(self._closeChan)

    def _closeChan(self):
        self.sendTCP([
            Msg(cmd=12, p1=self.sid, p2=self.cid),
        ])

        junk=[]
        while True:
            rep = self.recvTCP()
            if rep.cmd==12:
                break
            junk.append(rep)
        self.assertCAEqual(rep, cmd=12, p1=self.sid, p2=self.cid)
        self.sid = None
        self.assertListEqual(junk, [])

    def test_get(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=ioid)

        self.assertEqual(rep.body[:4], '\0\0\0\x2a')

    def test_put(self):
        self.openChan()
        ioid = 1102
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=1, p1=self.sid, p2=1101, body='\0\0\0\x2b'),
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=ioid)

        self.assertEqual(rep.body[:4], '\0\0\0\x2b')

    def test_put_callback(self):
        self.openChan()
        self.sendTCP([
            Msg(cmd=19, dtype=5, dcnt=1, p1=self.sid, p2=1101, body='\0\0\0\x2c'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=19, dtype=5, dcnt=1, p1=1, p2=1101)

        self.sendTCP([
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=1102),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=1102)

        self.assertEqual(rep.body[:4], '\0\0\0\x2c')

    def test_monitor(self):
        self.openChan()
        ioid = 1102
        # subscribe
        self.sendTCP([
            Msg(cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid,
                body=Msg._sub_body.pack(0.0, 0.0, 0.0, 1)), # DBE_VALUE
        ])

        # wait for initial update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], '\0\0\0\x2a')

        # Send a Put to trigger a subscription update
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=1, p1=self.sid, p2=1101, body='\0\0\0\x2d'),
        ])

        # wait for update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], '\0\0\0\x2d')

        # cancel subscription
        self.sendTCP([
            Msg(cmd=2, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        # wait for confirmation
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)

        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid, size=0)

if __name__=='__main__':
    import os
    if 'LOGLEVEL' in os.environ:
        logging.basicConfig(level=logging.getLevelName(os.environ['LOGLEVEL']))
    unittest.main()
