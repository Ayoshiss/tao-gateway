"""
Asking the chip for an attestation report.

Inside a SEV-SNP guest, `/dev/sev-guest` accepts an ioctl that hands 64 bytes of
caller data to the AMD Secure Processor and returns a report signed by the VCEK.
Those 64 bytes are the whole point: they are what binds a report to one specific
request, so a miner cannot produce an answer before being asked for it.

This is the half that needs hardware to run. It is deliberately thin: the request
and response encoding is pure and tested, and only the ioctl itself touches the
device.

Thin did not mean safe. Every bug found here was in the parts a laptop could not
reach, the ioctl number, the errno the kernel uses to report a short buffer, and
the byte order of the certificate table's GUIDs. Encoding tests written next to
the code they test share its assumptions and confirm them rather than check them.

Mapping onto the `Silicon` protocol takes one idea: a SEV-SNP chip does not sign
arbitrary messages, it produces a report bound to 64 bytes. So the message is
hashed to exactly 64 bytes with SHA-512 and used as `user_data`, and the whole
report becomes the "signature". Verification reverses it. The interface above
never changes.
"""

from __future__ import annotations

import logging
import pathlib
import struct
from typing import Final

from .certtable import parse_cert_table
from .report import REPORT_SIZE, parse_report

logger = logging.getLogger("sentinel.sevsnp.guest")

DEVICE: Final = "/dev/sev-guest"

#: struct snp_guest_request_ioctl {
#:     __u8  msg_version;   /* padded out to the alignment of the u64s below */
#:     __u64 req_data;
#:     __u64 resp_data;
#:     __u64 exitinfo2;
#: }
IOCTL_FORMAT: Final = "<BxxxxxxxQQQ"


def _iowr(type_: str, nr: int, size: int) -> int:
    """Linux `_IOWR(type, nr, size)`: direction 3 (read|write), size, type, nr."""
    return (3 << 30) | (size << 16) | (ord(type_) << 8) | nr


#: The struct's size is encoded *into* the ioctl number, and the kernel rejects
#: a mismatch with ENOTTY rather than anything descriptive. So derive it from
#: the same format used to pack the struct instead of writing a literal, the
#: u8 pads out to 32 bytes, and a hand-computed 24 fails only on real hardware.
SNP_GET_REPORT: Final = _iowr("S", 0x0, struct.calcsize(IOCTL_FORMAT))  # 0xC0205300

#: Same outer struct, different request body: `req_data` points at
#: `snp_ext_report_req` and the host attaches its certificate table.
SNP_GET_EXT_REPORT: Final = _iowr("S", 0x2, struct.calcsize(IOCTL_FORMAT))  # 0xC0205302

#: struct snp_report_req { u8 user_data[64]; u32 vmpl; u8 rsvd[28]; }
REQ_SIZE: Final = 96

#: struct snp_ext_report_req {
#:     struct snp_report_req data;   /* 96 bytes */
#:     __u64 certs_address;
#:     __u32 certs_len;
#: } , trailing padding to the u64 alignment brings it to 112.
EXT_REQ_FORMAT: Final = "<96sQI4x"

#: How the kernel says "your certificate buffer is too small". Note it surfaces
#: as EIO, *not* ENOSPC as the header's naming suggests: the errno reflects the
#: failed guest request while the real signal is `vmm_error` in the upper half
#: of exitinfo2. Keying on errno alone silently loses the certificates and sends
#: the caller to KDS for no reason, which is exactly the dependency this avoids.
VMM_ERR_INVALID_LEN: Final = 1
ERRNO_NOSPC: Final = 28
#: A host that provisions no certificates at all still needs a non-zero probe
#: buffer on some kernels, and an absurd size would be its own bug. This is only
#: a ceiling on what the two-call handshake is willing to believe.
MAX_CERTS_LEN: Final = 1 << 20
#: struct snp_report_resp { u8 data[4000]; }
RESP_SIZE: Final = 4000
#: The response opens with status, report_size and 24 reserved bytes; the
#: report itself starts after that header, not at offset zero.
RESP_HEADER_SIZE: Final = 32

MSG_VERSION: Final = 1


class GuestError(Exception):
    """The chip could not or would not produce a report."""


def available() -> bool:
    """Whether this machine is a SEV-SNP guest that can be asked for a report."""
    return pathlib.Path(DEVICE).exists()


def build_request(user_data: bytes, vmpl: int = 0) -> bytes:
    """Encode `struct snp_report_req`.

    `user_data` must be exactly 64 bytes: it lands verbatim in the report's
    REPORT_DATA field, and padding it silently would let two different requests
    produce the same binding.
    """
    if len(user_data) != 64:
        raise GuestError(f"user_data must be exactly 64 bytes, got {len(user_data)}")
    if not 0 <= vmpl <= 3:
        raise GuestError(f"vmpl must be 0-3, got {vmpl}")
    return user_data + struct.pack("<I", vmpl) + bytes(28)


def parse_response(resp: bytes) -> bytes:
    """Pull the raw report out of `struct snp_report_resp`."""
    if len(resp) < RESP_HEADER_SIZE + REPORT_SIZE:
        raise GuestError(
            f"response is {len(resp)} bytes, too short to contain a report"
        )
    status, report_size = struct.unpack_from("<II", resp, 0)
    if status != 0:
        raise GuestError(f"firmware returned status {status}")
    if report_size < REPORT_SIZE:
        raise GuestError(f"firmware reported {report_size} bytes, expected {REPORT_SIZE}")
    return resp[RESP_HEADER_SIZE:RESP_HEADER_SIZE + REPORT_SIZE]


def request_report(user_data: bytes, vmpl: int = 0, device: str = DEVICE) -> bytes:
    """Ask the chip for a report bound to `user_data`. Requires a SEV-SNP guest.

    The only function here that touches hardware, and confirmed against an AMD
    EPYC 7B13. The ioctl number is derived from the struct rather than written as
    a literal, because the size is encoded into it and the kernel rejects a
    mismatch with a bare ENOTTY: which is precisely how the original hand
    computed value failed.
    """
    import fcntl  # Linux-only; imported late so this module loads anywhere.

    req = build_request(user_data, vmpl)
    resp = bytearray(RESP_SIZE)

    # The ioctl struct holds pointers to the request and response buffers, so
    # both must stay alive and pinned for the duration of the call.
    req_buf = bytearray(req)
    req_addr = _address_of(req_buf)
    resp_addr = _address_of(resp)

    ioctl_struct = bytearray(struct.pack(IOCTL_FORMAT, MSG_VERSION, req_addr, resp_addr, 0))

    try:
        with open(device, "rb") as fd:
            fcntl.ioctl(fd, SNP_GET_REPORT, ioctl_struct, True)
    except FileNotFoundError as exc:
        raise GuestError(
            f"{device} not present; this is not a SEV-SNP guest"
        ) from exc
    except OSError as exc:
        _, _, _, exitinfo2 = struct.unpack(IOCTL_FORMAT, bytes(ioctl_struct))
        raise GuestError(f"ioctl failed: {exc} (exitinfo2=0x{exitinfo2:x})") from exc

    return parse_response(bytes(resp))


def build_ext_request(user_data: bytes, certs_addr: int, certs_len: int,
                      vmpl: int = 0) -> bytes:
    """Encode `struct snp_ext_report_req`."""
    return struct.pack(
        EXT_REQ_FORMAT, build_request(user_data, vmpl), certs_addr, certs_len
    )


def request_ext_report(
    user_data: bytes, vmpl: int = 0, device: str = DEVICE
) -> tuple[bytes, bytes]:
    """Ask the chip for a report *and* the host's certificate table.

    Returns `(report_blob, certs_blob)`. The certificate blob is empty when the
    host provisioned nothing, a normal outcome on some clouds, and the reason
    callers must handle it rather than assume certificates are always there.

    The buffer size is negotiated rather than guessed: ask with a zero-length
    buffer, let the kernel refuse with ENOSPC and report the length it wants,
    then ask again with exactly that. Guessing a size either wastes a page or
    silently truncates the chain, and a truncated chain fails verification much
    later, where the cause is far from obvious.
    """
    import fcntl

    def _call(fd, req_buf: bytearray, resp_buf: bytearray) -> None:
        ioctl_struct = bytearray(struct.pack(
            IOCTL_FORMAT, MSG_VERSION, _address_of(req_buf), _address_of(resp_buf), 0
        ))
        try:
            fcntl.ioctl(fd, SNP_GET_EXT_REPORT, ioctl_struct, True)
        except OSError as exc:
            _, _, _, exitinfo2 = struct.unpack(IOCTL_FORMAT, bytes(ioctl_struct))
            exc.exitinfo2 = exitinfo2  # type: ignore[attr-defined]
            raise

    resp = bytearray(RESP_SIZE)
    try:
        with open(device, "rb") as fd:
            # 1. Probe with no buffer; the kernel tells us how much it needs.
            probe = bytearray(build_ext_request(user_data, 0, 0, vmpl))
            certs_len = 0
            try:
                _call(fd, probe, resp)
            except OSError as exc:
                exitinfo2 = getattr(exc, "exitinfo2", 0)
                vmm_err = (exitinfo2 >> 32) & 0xFFFFFFFF
                if vmm_err != VMM_ERR_INVALID_LEN and exc.errno != ERRNO_NOSPC:
                    raise GuestError(
                        f"ext report ioctl failed: {exc} (exitinfo2=0x{exitinfo2:x})"
                    ) from exc
                # The kernel wrote the size it wants back into our request.
                _, _, certs_len = struct.unpack(EXT_REQ_FORMAT, bytes(probe))

            if certs_len == 0:
                # The probe succeeded outright: no certificates to fetch.
                return parse_response(bytes(resp)), b""
            if certs_len > MAX_CERTS_LEN:
                raise GuestError(f"host asked for an implausible {certs_len} certificate bytes")

            # 2. Ask again with exactly the buffer it asked for.
            certs = bytearray(certs_len)
            req = bytearray(build_ext_request(user_data, _address_of(certs), certs_len, vmpl))
            resp = bytearray(RESP_SIZE)
            _call(fd, req, resp)
            return parse_response(bytes(resp)), bytes(certs)

    except FileNotFoundError as exc:
        raise GuestError(f"{device} not present; this is not a SEV-SNP guest") from exc
    except OSError as exc:
        raise GuestError(
            f"ext report ioctl failed: {exc} "
            f"(exitinfo2=0x{getattr(exc, 'exitinfo2', 0):x})"
        ) from exc


def _address_of(buf: bytearray) -> int:
    """Stable address of a mutable buffer, for the ioctl's pointer fields."""
    import ctypes

    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


# --- Silicon protocol ---------------------------------------------------------

class SevSnpSilicon:
    """Real AMD silicon behind the same `Silicon` interface as `MockSilicon`.

    `sign()` returns a full attestation report as hex rather than a bare
    signature, because that is what a chip actually produces. The verifier
    understands both, so nothing upstream cares.
    """

    def __init__(self, vmpl: int = 0, device: str = DEVICE) -> None:
        if not pathlib.Path(device).exists():
            raise GuestError(
                f"{device} not present; SevSnpSilicon needs a SEV-SNP guest. "
                "Use MockSilicon for development."
            )
        self.vmpl = vmpl
        self.device = device
        self._chip_id: str | None = None
        self._certs: dict[str, bytes] | None = None
        self._measurement: str | None = None

    @property
    def chip_id(self) -> str:
        """CHIP_ID from a report. Cached: it does not change."""
        if self._chip_id is None:
            blob = request_report(bytes(64), self.vmpl, self.device)
            self._chip_id = parse_report(blob).chip_id_hex
        return self._chip_id

    @property
    def certificates(self) -> dict[str, bytes]:
        """The host's certificate table, as `{name: der}`.

        A report on its own cannot be checked: verifying it needs the VCEK, and
        historically that meant asking AMD's KDS. The extended report has the
        host hand the chain over with the proof instead, which is what lets a
        verifier work while AMD is unreachable. That is not hypothetical; KDS
        was refusing connections the day this path was written.

        Fetched once. The certificates are per-chip and per-firmware, so they do
        not change underneath a running miner; a firmware update replaces the VM.
        Empty when the host provisioned nothing, which callers must handle by
        falling back to KDS rather than assuming certificates are always present.
        """
        if self._certs is None:
            _, blob = request_ext_report(bytes(64), self.vmpl, self.device)
            self._certs = parse_cert_table(blob)
        return self._certs

    @property
    def measurement(self) -> str:
        """The launch measurement of this VM, hex, from a report.

        What the firmware hashed as it built the guest, so it identifies the
        image that is running. A miner reports it; it does not get to decide it.
        Cached because it is fixed for the life of the VM: changing the image
        means a new launch, and a new launch means a new measurement.

        Read this to *learn* the value once and pin it in a policy. Never read it
        to *populate* the policy at startup, which would have the code being
        checked supply the answer to the check.
        """
        if self._measurement is None:
            blob = request_report(bytes(64), self.vmpl, self.device)
            self._measurement = parse_report(blob).measurement.hex()
        return self._measurement

    def sign(self, message: bytes) -> str:
        """A report bound to `message`, hex encoded.

        SHA-512 gives exactly the 64 bytes REPORT_DATA holds, so the binding is
        the full digest with no truncation or padding.
        """
        import hashlib

        user_data = hashlib.sha512(message).digest()
        return request_report(user_data, self.vmpl, self.device).hex()

    def public_verifier(self):  # pragma: no cover - needs hardware
        raise GuestError(
            "verify SEV-SNP reports with SevSnpVerifier, which checks the AMD "
            "certificate chain; a bare public key is not sufficient"
        )
