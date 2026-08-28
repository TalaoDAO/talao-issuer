"""Small client for the openid4vc-hub issuance API."""

from __future__ import annotations

import base64
import io

import qrcode
import requests
from qrcode.image.svg import SvgPathImage


class HubError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class HubClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @property
    def headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _json_object(response: requests.Response) -> dict:
        try:
            payload = response.json()
        except ValueError as exc:
            raise HubError(
                "The hub returned invalid JSON", response.status_code
            ) from exc
        if not isinstance(payload, dict):
            raise HubError("The hub returned an invalid response", response.status_code)
        return payload

    def create_issuance(self, payload: dict) -> dict:
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/issuances",
                headers=self.headers,
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise HubError("The credential issuer is temporarily unavailable") from exc

        data = self._json_object(response)
        if response.status_code not in {200, 201}:
            description = data.get("error_description")
            error = data.get("error")
            raise HubError(
                description
                if isinstance(description, str)
                else error
                if isinstance(error, str)
                else "Credential issuance failed",
                response.status_code,
            )
        return data

    def get_issuance(self, issuance_id: str) -> dict:
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/issuances/{issuance_id}",
                headers=self.headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise HubError("Temporary connection issue") from exc

        data = self._json_object(response)
        if response.status_code != 200:
            description = data.get("error_description")
            error = data.get("error")
            raise HubError(
                description
                if isinstance(description, str)
                else error
                if isinstance(error, str)
                else "Cannot read issuance status",
                response.status_code,
            )
        return data


def qr_svg_data_uri(content: str) -> str:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(content)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"
