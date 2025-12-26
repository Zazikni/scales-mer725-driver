import hashlib
import json
import sys
import socket
import time
from typing import Optional, Tuple
import logging
from .utilities import get_json_from_bytearray


class Scales:
    def __init__(self, ip: str, port: int, password: str, protocol:str):

        self.ip: str = ip
        self.port: int = port
        self.__password: bytes = password.encode("ASCII")
        self.command_len_bytes: int = 4

        self.__file_chunk_limit = 60000
        if protocol not in ('TCP', 'UDP'):
            raise ValueError('Протокол должен быть TCP или UDP')
        self.__protocol = socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM
        self.__get_socket()

    def __del__(self):
        self.__socket.close()


    def __get_socket(self):
        try:
            self.__socket = socket.socket(socket.AF_INET, self.__protocol)
            self.__socket.connect((self.ip, self.port))
            logging.info(f"Cокет успешно создан\n")
        except Exception as e:
            logging.error(f"Не удалось создать сокет\n{e}")
            raise e

    def __file_creation_request_gen(self) -> bytes:
        """
        Формирует команду для весов.

        :return: Пакет с запросом на создание файла
        """
        payload = (
            Scales.Codes.JsonFileReceiving.FILE_CREATION_COMMAND_CODE + self.__password
        )
        package = self.__packet_header_gen(payload) + payload

        return Scales.tcp_command_len_generator(package, self.command_len_bytes) + package

    def __file_creation_status_request_gen(self) -> bytes:
        """
        Формирует команду для весов.

        :return: Пакет с запросом на получение статуса создания файла
        """
        payload = (
            Scales.Codes.JsonFileReceiving.FILE_CREATION_STATUS_COMMAND_CODE
            + self.__password
        )
        package = self.__packet_header_gen(payload) + payload
        return Scales.tcp_command_len_generator(package, self.command_len_bytes) + package

    def __hash_calculating_request_gen(self) -> bytes:
        """
        Формирует команду для весов.

        :return: Пакет с запросом на начало расчёта хэш-данных
        """
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.HASH_CALCULATING_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return Scales.tcp_command_len_generator(package, self.command_len_bytes) + package

    def __hash_calculating_status_request_gen(self) -> bytes:
        """
        Формирует команду для весов.

        :return: Пакет с запросом на получение статуса расчёта хэш-данных
        """
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.HASH_CALCULATING_STATUS_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return Scales.tcp_command_len_generator(package, self.command_len_bytes) + package

    def __file_transfer_init_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.FILE_RECEIVING_INITIATION_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return Scales.tcp_command_len_generator(package, self.command_len_bytes) + package

    def __send(self, data: bytes, label: str):
        logging.debug(f"[>] {label} | {len(data)} байт | HEX: {data.hex()} | {data}")
        self.__socket.sendall(data)

    # def __send_big_data(self, data: bytes, label: str):
    #     logging.debug(f"[>] {label} | {len(data)} байт | {list(data[:13])}")
    #     self.__socket.sendto(data, (self.ip, self.port))
    #
    def __recv_big_data(self, timeout: float = 20) -> Optional[tuple[bytes, tuple]]:
        self.__socket.settimeout(timeout)
        try:
            data, addr = self.__socket.recvfrom(65507)
            logging.debug(
                f"[<] От весов {addr} → {self.__socket.getsockname()[1]} | {len(data)} байт | {list(data[:17])}"
            )
            return data, addr
        except socket.timeout:
            logging.warning("Не удалось получить ответ от весов за отведенное время.")
            return None

    def __recv(
        self, timeout: float = 5, force_exit_if_timeout: bool = False
    ) -> Optional[tuple[bytes, tuple]]:
        self.__socket.settimeout(timeout)
        try:
            data, addr = self.__socket.recvfrom(2048)
            logging.debug(
                f"[<] От весов {addr} → {self.__socket.getsockname()[1]} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
            )
            for num, byte in enumerate(data):
                logging.debug(
                f"[<] Номер байта: {num+1} Значение байта: {byte.to_bytes().hex()}"
            )
            return data, addr
        except socket.timeout:
            logging.warning("Не удалось получить ответ от весов за отведенное время.")
            if force_exit_if_timeout:
                sys.exit(1)
            else:
                return None

    def get_products_json(self) -> dict:
        """
        Запрашивает данные с весов.

        :return: словарь с информацией о товарах на весах.
        """
        self.__send(
            self.__file_creation_request_gen(),
            "Пакет с запросом на создание файла",
        )
        scales_response, _ = self.__recv(force_exit_if_timeout=True)
        if scales_response[8].to_bytes() != Scales.Codes.ResponseCodes.SUCCESS:
            logging.warning("Ответ весов не удовлетворяет условиям.")

        while True:
            self.__send(
                self.__file_creation_status_request_gen(),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            scales_response, _ = self.__recv()
            if scales_response[8].to_bytes() == Scales.Codes.ResponseCodes.IN_PROGRESS:
                continue
            else:
                break
        self.__send(
            self.__hash_calculating_request_gen(),
            "Пакет с запросом на начало расчёта хэш-данных",
        )
        scales_response, _ = self.__recv()
        if scales_response[8].to_bytes() != Scales.Codes.ResponseCodes.SUCCESS:
            logging.warning("Ответ весов не удовлетворяет условиям.")
        file_hash:bytes = b''
        time.sleep(1)
        self.__send(
            self.__hash_calculating_status_request_gen(),
            "Пакет с запросом на получение статуса расчёта хэш-данных",
        )
        scales_response, _ = self.__recv()
        if scales_response[8].to_bytes() == Scales.Codes.ResponseCodes.SUCCESS:
            file_hash = scales_response[10:26]
        else:
            logging.warning("Ответ весов не удовлетворяет условиям.")


        file_data = bytearray()
        while True:
            self.__send(
                self.__file_transfer_init_request_gen(),
                "Пакет с запросом на получение порции файла",
            )
            time.sleep(0.3)
            data, address = self.__recv_big_data()
            is_last_chunk = data[9] == 1  # 10-й байт флаг последней порции
            file_data.extend(data[16:])
            if is_last_chunk:
                break

        return get_json_from_bytearray(file_data)

    # def __initial_file_transfer_request_gen(
    #     self, data: bytes, clear_database: bool = False
    # ) -> bytes:
    #     md5_hash = hashlib.md5(data).digest()
    #     payload = (
    #         Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE
    #         + self.__password
    #         + Scales.Codes.JsonFileTransfer.HASH_TRANSFER_CODE
    #         + md5_hash
    #         + Scales.Codes.JsonFileTransfer.FILE_SIZE_CODE
    #         + len(data).to_bytes(8, byteorder="big")
    #         + Scales.Codes.JsonFileTransfer.PRODUCTS_EXPORT_CODE
    #         + (
    #             Scales.Codes.JsonFileTransfer.CLEAR_DATABASE_TRUE_CODE
    #             if clear_database
    #             else Scales.Codes.JsonFileTransfer.CLEAR_DATABASE_FALSE_CODE
    #         )
    #     )
    #
    #     return self.__packet_header_gen(payload) + payload
    #
    # def __file_transfer_commands_gen(
    #     self,
    #     data: bytes,
    # ) -> Tuple[bytes, ...]:
    #     command = bytes([0xFF, 0x13])
    #     chunk_sending_code = bytes([0x03])
    #     offset_param = 0
    #     total_len = len(data)
    #     packets = []
    #
    #     while offset_param < total_len:
    #         # текущая порция данных
    #         chunk = data[offset_param : offset_param + self.__file_chunk_limit]
    #         is_last = offset_param + self.__file_chunk_limit >= total_len
    #
    #         is_last_byte = bytes([0x01]) if is_last else bytes([0x00])
    #         offset_bytes = offset_param.to_bytes(4, "little")
    #         chunk_len_bytes = len(chunk).to_bytes(2, "little")
    #
    #         payload = (
    #             command
    #             + self.__password
    #             + chunk_sending_code
    #             + is_last_byte
    #             + offset_bytes
    #             + chunk_len_bytes
    #             + chunk
    #         )
    #         packet = self.__packet_header_gen(payload) + payload
    #         packets.append(packet)
    #
    #         offset_param += self.__file_chunk_limit
    #
    #     return tuple(packets)
    #
    # def __transfered_file_check_command_gen(self):
    #     command = bytes([0xFF, 0x13])
    #     file_check_code = bytes([0x09])
    #     payload = command + self.__password + file_check_code
    #     return Scales.__packet_header_gen(payload) + payload
    #
    @staticmethod
    def __packet_header_gen(payload: bytes):
        if len(payload) < 255:
            return Scales.Codes.Global.STX + bytes([len(payload)])
        else:
            return (
                Scales.Codes.Global.STX + Scales.Codes.Global.UNLIMITED_PACKET_SIZE_CODE
            )

    @staticmethod
    def tcp_command_len_generator(package:bytes, length:int) -> bytes:
        return len(package).to_bytes(length, byteorder="little", signed=False)
    #
    # def send_json_products(self, data: dict) -> None:
    #     """
    #     Отправляет байтовые данные содержащие JSON с товарами на весы.
    #
    #     :param data: байтовые данные, содержащие JSON.
    #     :return: None
    #     """
    #     json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
    #         "utf-8"
    #     )
    #     response: bytes
    #     self.__send(
    #         self.__initial_file_transfer_request_gen(json_bytes, clear_database=True),
    #         "Пакет, содержащий хэш-данные файла и параметры",
    #     )
    #     response, _ = self.__recv(force_exit_if_timeout=True)
    #     if response != b"\x02\x03\xff\x13\x00":
    #         logging.error(f"Не удалось инициализировать передачу JSON файла на весы.")
    #         sys.exit(1)
    #     packets = self.__file_transfer_commands_gen(json_bytes)
    #     for packet in packets:
    #         self.__send_big_data(packet, "Пакет, содержащий порцию файла")
    #         response, _ = self.__recv()
    #         if response == b"\x02\x03\xff\x13\x00":
    #             continue
    #         else:
    #             logging.error(f"Не удалось загрузить порцию файла.")
    #             sys.exit(1)
    #     while True:
    #         self.__send(
    #             self.__transfered_file_check_command_gen(),
    #             "Пакет с запросом на проверку отправляемого файла",
    #         )
    #
    #         response, _ = self.__recv()
    #         if response == b"\x02\x06\xff\x13\x00\x01\x00\x00":
    #             time.sleep(1)
    #             continue
    #         elif response == b"\x02\x06\xff\x13\x00\x00\x00\x00":
    #             break
    #         elif response == b"\x02\x06\xff\x13\x00\x02\x00\x00":
    #             logging.error(f"Файл обработан с ошибкой.  Загрузка не удалась.")
    #             sys.exit(1)
    #
    # def get_all_json_transfer_commands(self, json_bytes) -> dict:
    #     """
    #     Метод для тестирования. Генерирует команды для отправки данных JSON на весы.
    #
    #     :return: словарь с сгенерированными командами для отправки байтовых данных JSON.
    #     """
    #     res = dict()
    #     res["1"] = self.__initial_file_transfer_request_gen(
    #         data=json_bytes, clear_database=True
    #     )
    #     res["2"] = self.__initial_file_transfer_request_gen(
    #         data=json_bytes, clear_database=False
    #     )
    #     res["3"] = self.__file_transfer_commands_gen(json_bytes)
    #     res["4"] = self.__transfered_file_check_command_gen()
    #
    #     return res

    class Codes:
        """
        Cодержит все коды взаимодействия с весами.
        """

        class Global:
            STX = bytes([0x02])  # StartOfText
            UNLIMITED_PACKET_SIZE_CODE = bytes([0xFF])

        class ResponseCodes:
            SUCCESS = bytes([0x00])
            IN_PROGRESS = bytes([0xac])

        class JsonFileReceiving:
            FILE_CREATION_COMMAND_CODE = bytes([0xFF, 0x14])
            FILE_CREATION_STATUS_COMMAND_CODE = bytes([0xFF, 0x15])
            HASH_CALCULATING_COMMAND_CODE = bytes([0xFF, 0x12])
            HASH_CALCULATING_STAGE_CODE = bytes([0x06])
            HASH_CALCULATING_STATUS_STAGE_CODE = bytes([0x07])
            FILE_RECEIVING_INITIATION_STAGE_CODE = bytes([0x03])

        class JsonFileTransfer:
            FILE_TRANSFER_COMMAND_CODE = bytes([0xFF, 0x13])
            HASH_TRANSFER_CODE = bytes([0x02])
            FILE_SIZE_CODE = bytes([0x04])
            PRODUCTS_EXPORT_CODE = bytes([0x01])
            CLEAR_DATABASE_TRUE_CODE = bytes([0x00])
            CLEAR_DATABASE_FALSE_CODE = bytes([0x01])
            LAST_CHUNK_TRUE_CODE = bytes([0x01])
            LAST_CHUNK_FALSE_CODE = bytes([0x00])
            CHUNK_SENDING_CODE = bytes([0x03])
