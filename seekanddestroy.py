#!/usr/bin/python

'''
Change NUM_CORES=# of how many cores do you want to use (Script tested on i7-4500U 8 Cores - 5 K/s per Core. 3,456,000 Private Keys generated per day)
'''

import base58
import binascii
import datetime as dt
import ecdsa
import hashlib
import multiprocessing
import os
import smtplib
import time
from datetime import datetime


class Seek:
    FILENAME = 'bit.txt'
    LOG_EVERY_N = 500
    NUM_CORES = 16  # number of cores to use

    def __init__(self, ):
        self.pub_keys = self.prepare_stored_key()

        print()

    @staticmethod
    def prepare_stored_key():
        with open(Seek.FILENAME) as f:
            return [p.replace('\n', '') for p in f]

    @staticmethod
    def ripemd160(x):
        d = hashlib.new('ripemd160')
        d.update(x)
        return d

    @staticmethod
    def keygen():
        priv_key = os.urandom(32)
        fullkey = '80' + binascii.hexlify(priv_key).decode()
        sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
        sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
        WIF = base58.b58encode(binascii.unhexlify(fullkey + sha256b[:8]))

        # get public key , uncompressed address starts with "1"
        try:
            sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
        except Exception:
            return '', ''

        vk = sk.get_verifying_key()
        publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
        hash160 = Seek.ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
        publ_addr_a = b"\x00" + hash160
        checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
        publ_addr_b = base58.b58encode(publ_addr_a + checksum)
        priv = WIF.decode()
        pub = publ_addr_b.decode()

        return priv, pub

    def searching(self, pub):
        if pub in self.pub_keys:
            return True
        else:
            return False

    def seek(self, r):
        start_time = dt.datetime.today().timestamp()
        i = 0
        print("Core " + str(r) + ":  Searching Private Key..")
        while True:
            i = i + 1
            # generate private key , uncompressed WIF starts with "5"

            priv, pub = Seek.keygen()

            time_diff = dt.datetime.today().timestamp() - start_time
            if (i % Seek.LOG_EVERY_N) == 0:
                print('Core :' + str(r) + " K/s = " + str(i / time_diff))
                start_time = dt.datetime.today().timestamp()
                i = 0

            if self.searching(pub):
                msg = "\nPublic: " + str(pub) + " ---- Private: " + str(priv) + "YEI"
                print('WINNER WINNER CHICKEN DINNER!!! ---- ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                      pub, priv)
                print(msg)

                try:
                    server = smtplib.SMTP("smtp.gmail.com", 587)
                    server.ehlo()
                    server.starttls()
                    server.login("example@gmail.com", "password")
                    fromaddr = "example@gmail.com"
                    toaddr = "example@gmail.com"
                    server.sendmail(fromaddr, toaddr, msg)
                except Exception as e:
                    print('SMTP Error')

                f = open('Wallets.txt', 'a')
                f.write(priv)
                f.write('     ')
                f.write(pub)
                f.write('\n')
                f.close()
                time.sleep(30)

    def run(self):
        jobs = []
        for r in range(Seek.NUM_CORES):
            p = multiprocessing.Process(target=self.seek, args=(r,))
            jobs.append(p)
            p.start()


if __name__ == '__main__':
    seek = Seek()
    #seek.seek(0)
    seek.run()
