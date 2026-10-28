"""SMS delivery for the Proof of Phone website verification code."""

import logging

LOGGER = logging.getLogger(__name__)
BLOCKED_COUNTRY_PREFIXES = ("254", "255")


def send_verification_code(phone_number: str, code: str, settings) -> bool:
    from smsapi.client import SmsApiComClient
    from smsapi.exception import SmsApiException

    destination = phone_number.removeprefix("+")
    if destination.startswith(BLOCKED_COUNTRY_PREFIXES):
        LOGGER.warning("SMS destination country is blocked")
        return False
    if not settings.sms_token:
        raise RuntimeError("SMS_API_TOKEN is not configured")

    try:
        client = SmsApiComClient(access_token=settings.sms_token)
        results = client.sms.send(
            to=destination,
            timeout=settings.hub_request_timeout,
            message=f"Your Proof of Phone verification code is: {code}. Enter it on the issuer website. Valid for 5 minutes.",
        )
    except SmsApiException:
        LOGGER.warning("SMS delivery failed")
        return False

    return any(result.error is None for result in results)
