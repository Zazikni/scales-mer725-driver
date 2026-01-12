import socket

import pytest

from scales.scales import Scales


def make_scales(password: str = "pw", chunk_limit: int = 3) -> Scales:
    scales = Scales.__new__(Scales)
    scales.command_len_bytes = 4
    scales._Scales__password = password.encode("ascii")
    scales._Scales__file_chunk_limit = chunk_limit
    return scales


def test_tcp_command_len_generator_encodes_length():
    package = b"abcdef"
    assert Scales._Scales__tcp_command_len_generator(package, 4) == (6).to_bytes(
        4, "little"
    )


def test_packet_header_gen_small_payload():
    payload = b"abc"
    header = Scales._Scales__packet_header_gen(payload)
    assert header == Scales.Codes.Global.STX + bytes([len(payload)])


def test_packet_header_gen_unlimited_payload():
    payload = b"a" * 255
    header = Scales._Scales__packet_header_gen(payload)
    assert header == Scales.Codes.Global.STX + Scales.Codes.Global.UNLIMITED_PACKET_SIZE_CODE


def test_is_transient_socket_error():
    assert Scales._Scales__is_transient_socket_error(socket.timeout()) is True
    assert Scales._Scales__is_transient_socket_error(OSError(111, "Connection refused")) is True
    assert Scales._Scales__is_transient_socket_error(ValueError("nope")) is False


def test_format_socket_error_includes_errno():
    error = OSError(111, "Connection refused")
    message = Scales._Scales__format_socket_error(error)
    assert "Connection refused" in message
    assert "errno=111" in message


def test_file_transfer_commands_gen_chunks_and_offsets():
    scales = make_scales(password="pw", chunk_limit=3)
    data = b"abcdefg"

    packets = scales._Scales__file_transfer_commands_gen(data)

    assert len(packets) == 3

    for index, packet in enumerate(packets):
        package_len = int.from_bytes(packet[:4], "little")
        package = packet[4:]
        assert package_len == len(package)

        header = package[:2]
        payload = package[2:]
        assert header[0:1] == Scales.Codes.Global.STX
        assert header[1] == len(payload)

        command_len = len(Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE)
        command = payload[:command_len]
        assert command == Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE

        offset_start = command_len + len(scales._Scales__password) + 1 + 1
        offset = int.from_bytes(payload[offset_start : offset_start + 4], "little")

        chunk_len_start = offset_start + 4
        chunk_len = int.from_bytes(payload[chunk_len_start : chunk_len_start + 2], "little")

        chunk = payload[chunk_len_start + 2 :]

        assert offset == index * 3
        assert chunk == data[offset : offset + chunk_len]

    last_payload = packets[-1][4 + 2 :]
    last_flag_index = len(Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE) + len(
        scales._Scales__password
    ) + 1
    last_flag = last_payload[last_flag_index:last_flag_index + 1]
    assert last_flag == Scales.Codes.JsonFileTransfer.LAST_CHUNK_TRUE_CODE
