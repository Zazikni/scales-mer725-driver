import pytest

from scales.utilities import get_json_from_bytearray


def test_get_json_from_bytearray_dict():
    data = b'{"name": "apple", "price": 100}'
    assert get_json_from_bytearray(data) == {"name": "apple", "price": 100}


def test_get_json_from_bytearray_list_wraps_items():
    data = b'[{"sku": "1"}, {"sku": "2"}]'
    assert get_json_from_bytearray(data) == {"items": [{"sku": "1"}, {"sku": "2"}]}


def test_get_json_from_bytearray_invalid_returns_none(caplog):
    data = b"not-json"
    assert get_json_from_bytearray(data) is None
    assert any("Ошибка декодирования JSON" in record.message for record in caplog.records)
