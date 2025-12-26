import hashlib
import json
import sys
import socket
import time
from json import JSONDecodeError
from typing import Optional, Tuple
import logging

from .exceptions import DeviceError
from .utilities import get_json_from_bytearray


class Scales:
    def __init__(self, ip: str, port: int, password: str, protocol: str):

        self.ip: str = ip
        self.port: int = port
        self.__password: bytes = password.encode("ASCII")
        self.command_len_bytes: int = 4

        self.__file_chunk_limit = 60000
        if protocol not in ("TCP", "UDP"):
            raise ValueError("Протокол должен быть TCP или UDP")
        self.__protocol = socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM
        self.__get_socket()

    def __del__(self):
        logging.info(
            f"Сокет {self.__socket.getsockname()} → {self.__socket.getpeername()} ЗАКРЫТ"
        )
        self.__socket.close()

    def __get_socket(self):
        try:
            self.__socket = socket.socket(socket.AF_INET, self.__protocol)
            self.__socket.connect((self.ip, self.port))
            logging.info(
                f"Сокет успешно создан {self.__socket.getsockname()} → {self.__socket.getpeername()}"
            )
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

        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

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
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

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
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

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
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __file_transfer_init_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.FILE_RECEIVING_INITIATION_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __send(self, data: bytes, label: str, bigdata: bool = False) -> None:
        if self.__protocol == socket.SOCK_STREAM:
            self.__socket.sendall(data)
            if not bigdata:
                logging.debug(
                    f"[>] На весы TCP {self.__socket.getsockname()} → {self.__socket.getpeername()} {label} | {len(data)} байт | HEX: {data.hex()} | {data}"
                )
            else:
                logging.debug(
                    f"[>] На весы TCP {self.__socket.getsockname()} → {self.__socket.getpeername()} {label} | {len(data)} байт | {list(data[:17])}"
                )

        else:
            self.__socket.sendto(data, (self.ip, self.port))
            if not bigdata:
                logging.debug(
                    f"[>] На весы UDP {self.__socket.getsockname()} → {self.__socket.getpeername()} {label} | {len(data)} байт | HEX: {data.hex()} | {data}"
                )
            else:
                logging.debug(
                    f"[>] На весы UDP {self.__socket.getsockname()} → {self.__socket.getpeername()} {label} | {len(data)} байт | {list(data[:17])}"
                )

    def __recv(
        self, bufsize: int = 2048, timeout: float = 5, bigdata: bool = False
    ) -> Optional[bytes]:
        self.__socket.settimeout(timeout)
        try:

            if self.__protocol == socket.SOCK_STREAM:
                data = self.__recv_tcp_frame(timeout)
                if not bigdata:
                    logging.debug(
                        f"[<] От весов TCP {self.__socket.getpeername()} → {self.__socket.getsockname()} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
                    )
                else:
                    logging.debug(
                        f"[<] От весов TCP {self.__socket.getpeername()} → {self.__socket.getsockname()} | {len(data)} байт | {list(data[:17])}"
                    )
                return data if data else None
            else:
                data, _ = self.__socket.recvfrom(bufsize)
                if not bigdata:

                    logging.debug(
                        f"[<] От весов UDP {self.__socket.getpeername()} → {self.__socket.getsockname()} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
                    )
                else:
                    logging.debug(
                        f"[<] От весов UDP {self.__socket.getpeername()} → {self.__socket.getsockname()} | {len(data)} байт | {list(data[:17])}"
                    )
                return data

        except socket.timeout:
            logging.warning("Не удалось получить ответ от весов за отведенное время.")
            return None

    def __recv_tcp_frame(self, timeout: float) -> bytes:

        raw_len = self.__recv_exact(self.command_len_bytes, timeout)
        frame_len = int.from_bytes(raw_len, byteorder="little", signed=False)

        body = self.__recv_exact(frame_len, timeout)
        return body

    def __recv_exact(self, n: int, timeout: float) -> bytes:
        self.__socket.settimeout(timeout)
        chunks = []
        received = 0

        while received < n:
            chunk = self.__socket.recv(n - received)
            if not chunk:
                raise ConnectionResetError(
                    "TCP соединение закрыто удаленной стороной (recv вернул 0 байт)."
                )
            chunks.append(chunk)
            received += len(chunk)

        return b"".join(chunks)

    def __response_validator(
        self, response: bytes, length: int, cond: str = "eq", min_length: int = 4
    ) -> None:
        if response is None:
            raise DeviceError("Ответ от весов не получен.")
        if len(response) < min_length:
            raise DeviceError(
                f"Короткий ответ от весов: {len(response)} байт, ожидалось ≥ {min_length}"
            )
        if cond == "eq":
            if not (len(response) == length):
                raise DeviceError(
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине ."
                )
        elif cond == "gt":
            if not (len(response) > length):
                raise DeviceError(
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине ."
                )
        elif cond == "lt":
            if not (len(response) < length):
                raise DeviceError(
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине ."
                )

    def get_products_json(self) -> dict:
        """
        Запрашивает данные с весов.

        :return: Словарь с информацией о товарах на весах.
        """
        logging.info(
            f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} инициирован процесс получения JSON списка товаров."
        )
        self.__send(
            self.__file_creation_request_gen(),
            "Пакет с запросом на создание файла",
        )
        scales_response = self.__recv()
        self.__response_validator(scales_response, length=5)

        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")

        while True:
            self.__send(
                self.__file_creation_status_request_gen(),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            scales_response = self.__recv()
            self.__response_validator(scales_response, length=5)
            if scales_response[4] == Scales.Codes.ResponseCodes.IN_PROGRESS:
                continue
            else:
                break

        self.__send(
            self.__hash_calculating_request_gen(),
            "Пакет с запросом на начало расчёта хэш-данных",
        )

        scales_response = self.__recv()
        self.__response_validator(scales_response, length=5)
        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")
        file_hash: bytes = b""
        time.sleep(1)

        self.__send(
            self.__hash_calculating_status_request_gen(),
            "Пакет с запросом на получение статуса расчёта хэш-данных",
        )
        scales_response = self.__recv()
        self.__response_validator(scales_response, length=22)
        if scales_response[4] == Scales.Codes.ResponseCodes.SUCCESS:
            pass
            # file_hash = scales_response[10:26]
        else:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")

        file_data = bytearray()
        while True:
            self.__send(
                self.__file_transfer_init_request_gen(),
                "Пакет с запросом на получение порции файла",
            )
            time.sleep(0.3)
            data = self.__recv(65507, timeout=10, bigdata=True)
            self.__response_validator(data, length=12, cond="gt")
            try:
                is_last_chunk = data[5] == 1  # 10-й байт флаг последней порции
                file_data.extend(data[12:])
            except IndexError:
                raise DeviceError("Ошибка при получении порции файла.")
            if is_last_chunk:
                break

        try:
            json_data = get_json_from_bytearray(file_data)
            logging.info(
                f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} данные товаров в формате JSON получены."
            )
            return json_data

        except JSONDecodeError as e:
            logging.error("Не удалось конвертировать  bytearray в dict ")
            raise e

    def __initial_file_transfer_request_gen(
        self, data: bytes, clear_database: bool = False
    ) -> bytes:
        """
        Формирует команду для весов.

        :return: Пакет, содержащий хэш-данные файла и параметры
        """
        md5_hash = hashlib.md5(data).digest()
        payload = (
            Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileTransfer.HASH_TRANSFER_CODE
            + md5_hash
            + Scales.Codes.JsonFileTransfer.FILE_SIZE_CODE
            + len(data).to_bytes(8, byteorder="big")
            + Scales.Codes.JsonFileTransfer.PRODUCTS_EXPORT_CODE
            + (
                Scales.Codes.JsonFileTransfer.CLEAR_DATABASE_TRUE_CODE
                if clear_database
                else Scales.Codes.JsonFileTransfer.CLEAR_DATABASE_FALSE_CODE
            )
        )
        package = self.__packet_header_gen(payload) + payload
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __file_transfer_commands_gen(
        self,
        data: bytes,
    ) -> Tuple[bytes, ...]:
        """
        Формирует команду для весов.

        :return: Пакеты, содержащие порцию файла
        """
        command = bytes([0xFF, 0x13])
        chunk_sending_code = bytes([0x03])
        offset_param = 0
        total_len = len(data)
        packets = []

        while offset_param < total_len:
            # текущая порция данных
            chunk = data[offset_param : offset_param + self.__file_chunk_limit]
            is_last = offset_param + self.__file_chunk_limit >= total_len

            is_last_byte = bytes([0x01]) if is_last else bytes([0x00])
            offset_bytes = offset_param.to_bytes(4, "little")
            chunk_len_bytes = len(chunk).to_bytes(2, "little")

            payload = (
                command
                + self.__password
                + chunk_sending_code
                + is_last_byte
                + offset_bytes
                + chunk_len_bytes
                + chunk
            )
            package = self.__packet_header_gen(payload) + payload
            packets.append(
                Scales.tcp_command_len_generator(package, self.command_len_bytes)
                + package
            )

            offset_param += self.__file_chunk_limit

        return tuple(packets)

    def __transfered_file_check_command_gen(self):
        """

        Формирует команду для весов.

        :return: Пакет с запросом на проверку отправляемого файла
        """
        command = bytes([0xFF, 0x13])
        file_check_code = bytes([0x09])
        payload = command + self.__password + file_check_code
        package = self.__packet_header_gen(payload) + payload
        return (
            Scales.tcp_command_len_generator(package, self.command_len_bytes) + package
        )

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
    def tcp_command_len_generator(package: bytes, length: int) -> bytes:
        return len(package).to_bytes(length, byteorder="little", signed=False)

    def send_json_products(self, data: dict) -> None:
        """
        Отправляет байтовые данные содержащие JSON с товарами на весы.

        :param data: Байтовые данные, содержащие JSON.
        :return: None
        """
        logging.info(
            f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} инициирован процесс отправки JSON списка товаров."
        )
        json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        scales_response: bytes
        self.__send(
            self.__initial_file_transfer_request_gen(json_bytes, clear_database=True),
            "Пакет, содержащий хэш-данные файла и параметры",
        )
        scales_response = self.__recv()
        self.__response_validator(scales_response, length=5)
        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError(
                "Не удалось инициализировать передачу JSON файла на весы. Ошибка на этапе передачи хэш-данных файла и параметров."
            )
        packets = self.__file_transfer_commands_gen(json_bytes)
        for packet in packets:
            self.__send(packet, "Пакет, содержащий порцию файла", bigdata=True)
            scales_response = self.__recv()
            self.__response_validator(scales_response, length=5)
            if scales_response[4] == Scales.Codes.ResponseCodes.SUCCESS:
                continue
            else:
                raise DeviceError(
                    "Попытка загрузить порцию файла завершилась неудачей."
                )
        while True:
            self.__send(
                self.__transfered_file_check_command_gen(),
                "Пакет с запросом на проверку отправляемого файла",
            )
            scales_response = self.__recv()
            self.__response_validator(scales_response, length=8)
            if scales_response[5] == Scales.Codes.ResponseCodes.IN_PROGRESS_FILE:
                time.sleep(1)
                logging.info(
                    f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} файл еще находится на стадии проверки устройством."
                )
                continue
            elif scales_response[5] == Scales.Codes.ResponseCodes.SUCCESS:
                logging.info(
                    f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} файл успешно обработан устройством."
                )
                break
            elif scales_response[5] == Scales.Codes.ResponseCodes.ERROR_FILE:
                raise DeviceError(
                    f"[!] Сокет {self.__socket.getpeername()} → {self.__socket.getsockname()} файл обработан с ошибкой.  Загрузка не удалась."
                )

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
        Содержит все коды взаимодействия с весами.
        """

        class Global:
            STX = bytes([0x02])  # StartOfText
            UNLIMITED_PACKET_SIZE_CODE = bytes([0xFF])

        class ResponseCodes:
            SUCCESS = 0x00
            ERROR_FILE = 0x02
            IN_PROGRESS = 0xAC
            IN_PROGRESS_FILE = 0x01

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
