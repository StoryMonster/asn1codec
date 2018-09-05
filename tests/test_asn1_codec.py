import pytest
import os
from asn1_codec import Asn1Codec


@pytest.fixture()
def asn_data():
    data = ''
    with open("test.asn", "r") as fd:
        data = fd.read()
    return data


@pytest.fixture()
def asn1codec(request, asn_data):
    asn1codec = Asn1Codec("output.py", "output")
    asn1codec.compile(asn_data)
    return asn1codec


def test_asn1_decode(asn1codec):
    expect = {"carrierFreq": 12, "cellReselectionPriority": 1}
    _, actual = asn1codec.decode("uper", "json", "FreqPriorityNR", "00001840")
    assert expect == eval(actual)

def test_asn1_encode(asn1codec):
    message = "{carrierFreq 12, cellReselectionPriority 1}"
    _, encoded = asn1codec.encode("uper", "asn1", "FreqPriorityNR", message)
    assert "00001840" == encoded


