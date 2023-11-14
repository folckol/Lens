import base64
import time
from datetime import datetime, timezone
import ssl
import cloudscraper
import requests
import ua_generator
import warnings

import web3
from eth_account.messages import encode_defunct
from logger import logger
from web3.auto import w3

warnings.filterwarnings("ignore", category=DeprecationWarning)

class Account:

    def __init__(self, address, private, proxy):

        # print(address)
        self.address, self.private = address, private
        self.session = self._make_scraper
        self.session.proxies = {"http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
                                "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.session.headers.update({
                                     "user-agent": ua_generator.generate().text,
                                     'content-type': 'application/json'})

    def Registration(self):
        while True:
            try:
                self.nonce = self._get_nonce
                break
            except:
                pass

        msg = self._get_message_to_sign

        message = encode_defunct(text=msg)
        signed_message = w3.eth.account.sign_message(message, private_key=self.private)
        signature = signed_message["signature"].hex()

        payload = {'message': msg,
                   'nonce': self.nonce,
                   'signature': signature}

        with self.session.post('https://waitlist-server.lens.dev/auth/verify', json=payload) as response:
            return response.json()


    @property
    def _get_message_to_sign(self) -> str:

        return f"waitlist.lens.xyz wants you to sign in with your Ethereum account:\n{self.address}\n\nSign in with Ethereum to the Lens Waitlist app.\n\nURI: https://waitlist.lens.xyz\nVersion: 1\nChain ID: 137\nNonce: {self.nonce}\nIssued At: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}"

    @property
    def _get_nonce(self) -> str:

        with self.session.get('https://waitlist-server.lens.dev/auth/nonce') as response:
            return response.json()['nonce']


    @property
    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )



if __name__ == '__main__':

    data_p = []
    data = []
    with open('InputData/AddressPrivate.txt', 'r') as file:
        for i in file:
            data.append(i.rstrip().split(':'))

    with open('InputData/Proxies.txt', 'r') as file:
        for i in file:
            data_p.append(i.rstrip())

    mobileProxy = ''
    changeIpLink = ''
    count = 750
    while count<len(data)+1:

        requests.get(changeIpLink)
        time.sleep(10)

        l = count-1
        while True:
            acc = Account(address=web3.Web3.to_checksum_address(data[l][0]),
                          proxy=mobileProxy,
                          private=data[l][-1])
            result = acc.Registration()
            # print(result)
            if 'message' in result and result['message'] == 'Too many requests, please try again later.':
                logger.error(f'{count} - Ошибка в регистрации, сайт принял слишком много запросов, повторная попытка')
            else:
                if result['success'] == True:

                    logger.success(f'{count} - Регистрация прошла успешно')
                    break

                else:

                    logger.error(f'{count} - Неизвестная ошибка - {result}')
                    break

        count+=1













