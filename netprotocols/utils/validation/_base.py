#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from abc import ABC


class Validator(ABC):
    """Base class for descriptors of managed attributes in classes that
    require the validation of fields before assignment/manipulation."""

    def __get__(self, instance, owner=None) -> str:
        return self._value

    def __set__(self, instance, value: str) -> None:
        self._value = self.validate(value)

    @staticmethod
    def validate(value: str) -> str:
        ...
