#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"


class InvalidManufacturerCode(Exception):
    def __init__(self, message, code: int = 1):
        super().__init__(message)
        self.code = code


class InvalidMACAddressException(Exception):
    def __init__(self, message, code: int = 1):
        super().__init__(message)
        self.code = code


class InvalidIPv4AddressException(Exception):
    def __init__(self, message, code: int = 1):
        super().__init__(message)
        self.code = code
