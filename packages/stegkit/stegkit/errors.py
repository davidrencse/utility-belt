class StegKitError(Exception):
    """Base error shown by the command-line interface."""


class CapacityError(StegKitError):
    """Carrier does not have enough room for the framed payload."""


class DecodeError(StegKitError):
    """Carrier does not contain a valid StegKit payload."""

