"""Restricted delivery of an existing offer to an explicitly enabled cloud wallet."""
import re
from urllib.parse import urlsplit
import requests


class WalletDeliveryError(RuntimeError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.status = status


def validate_address(address, settings):
    try:
        if len(address)>2048 or any(ord(char)<33 for char in address):
            raise ValueError()
        parsed=urlsplit(address)
        parsed.port
        allowed=set(settings.wallet_delivery_origins)
        # Local HTTP is limited to explicit loopback addresses in local mode.
        if parsed.scheme=='http':
            if settings.environment!='local' or parsed.hostname not in {'127.0.0.1','localhost','::1'}:
                raise ValueError()
        elif parsed.scheme!='https':
            raise ValueError()
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or f'{parsed.scheme}://{parsed.netloc}' not in allowed
                or not re.fullmatch(r'/wallet-inbox/[A-Za-z0-9_-]{43}',parsed.path)):
            raise ValueError()
    except (ValueError,TypeError):
        raise WalletDeliveryError('invalid_wallet_address',
            'Enter a supported wallet receiving address. Copy it from your Business or Agent wallet.') from None
    return address


def deliver_offer(address, offer, settings):
    address=validate_address(address,settings)
    try:
        # Never reuse HubClient headers: the Hub API key must not reach a wallet.
        with requests.post(address,json={'offer':offer},headers={'Accept':'application/json'},
                           timeout=(3,10),allow_redirects=False,stream=True) as response:
            if response.status_code not in {200,201}:
                raise WalletDeliveryError('wallet_delivery_failed',
                    'The wallet did not accept the offer. Check its address or try again later.',502)
            chunks=[]
            size=0
            for chunk in response.iter_content(8192):
                size+=len(chunk)
                if size>65536:
                    raise WalletDeliveryError('wallet_delivery_failed','The wallet returned an invalid response.',502)
                chunks.append(chunk)
            import json
            try:
                payload=json.loads(b''.join(chunks))
            except (ValueError,UnicodeError):
                payload=None
            if (not isinstance(payload,dict) or payload.get('status')!='offer_received'
                    or payload.get('requires_owner_approval') is not True):
                raise WalletDeliveryError('wallet_delivery_failed','The wallet did not confirm receipt of the offer.',502)
    except requests.RequestException:
        raise WalletDeliveryError('wallet_unavailable',
            'The wallet could not be reached. Check that it is running and try again.',502) from None
