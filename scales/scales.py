import hashlib
import json
import sys
import socket
import time
from json import JSONDecodeError
from typing import Optional, Tuple
import logging

import scales
from .exceptions import DeviceError
from .utilities import get_json_from_bytearray


class Scales:
    def __init__(
        self,
        ip: str,
        port: int,
        password: str,
        *,
        connect_timeout: float = 3.0,
        default_timeout: float = 5.0,
        retries: int = 2,
        retry_delay: float = 0.5,
        auto_reconnect: bool = True,
    ):
        self.ip: str = ip
        self.port: int = port
        self.__password: bytes = password.encode("ASCII")
        self.command_len_bytes: int = 4

        self.__file_chunk_limit = 60000

        self.__protocol =  socket.SOCK_STREAM

        self.__connect_timeout = float(connect_timeout)
        self.__default_timeout = float(default_timeout)
        self.__retries = int(retries)
        self.__retry_delay = float(retry_delay)
        self.__auto_reconnect = bool(auto_reconnect)
        self.__connect_with_retries()

    def __del__(self):
        try:
            self.__socket.close()
            logging.info(
                f"Сокет {self.__socket.getsockname()} ←→ {self.__socket.getpeername()} ЗАКРЫТ"
            )
        except Exception:
            pass

    # --------- Низкоуровневые сетевые утилиты ---------

    @staticmethod
    def __is_transient_socket_error(e: BaseException) -> bool:
        """
        Возвращает True для ошибок, которые обычно означают "устройство выключено/недоступно/соединение оборвано".
        """
        if isinstance(
            e,
            (
                socket.timeout,
                TimeoutError,
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ),
        ):
            return True

        if isinstance(e, OSError):
            # Windows: e.winerror, POSIX: e.errno
            win = getattr(e, "winerror", None)
            err = getattr(e, "errno", None)

            # Частые сетевые/соединительные ошибки
            transient_win = {
                10054,
                10061,
                10060,
                10065,
                10051,
                10050,
            }
            transient_posix = {
                104,
                111,
                110,
                113,
                101,
                100,
                32,
            }

            if win in transient_win:
                return True
            if err in transient_posix:
                return True

        return False

    @staticmethod
    def __format_socket_error(e: BaseException) -> str:
        if isinstance(e, OSError):
            win = getattr(e, "winerror", None)
            err = getattr(e, "errno", None)
            parts = [str(e)]
            if win is not None:
                parts.append(f"winerror={win}")
            if err is not None:
                parts.append(f"errno={err}")
            return ", ".join(parts)
        return str(e)

    def __reconnect(self) -> None:
        """
        Переоткрывает сокет (TCP после reset/refused).
        """
        try:
            try:
                self.__socket.close()
            except Exception:
                pass
        finally:
            self.__connect_with_retries()

    def __connect_with_retries(self) -> None:
        """
        Унифицированное подключение/переподключение с повторами.
        Для сценариев, когда порт временно недоступен.
        """
        last_exc: BaseException | None = None

        # retries=2 => всего 3 попытки
        total_attempts = self.__retries + 1 if self.__retries >= 0 else 1

        for attempt in range(1, total_attempts + 1):
            try:
                self.__get_socket()
                return
            except DeviceError as e:
                last_exc = e
                logging.error(
                    "Не удалось подключиться к весам (%d/%d): %s",
                    attempt,
                    total_attempts,
                    e,
                )
                if attempt < total_attempts:
                    time.sleep(self.__retry_delay)

        if isinstance(last_exc, DeviceError):
            raise last_exc
        raise DeviceError(
            "Не удалось подключиться к устройству (неизвестная ошибка)."
        ) from last_exc

    def __get_socket(self):
        try:
            self.__socket = socket.socket(socket.AF_INET, self.__protocol)

            if self.__protocol == socket.SOCK_STREAM:
                self.__socket.settimeout(self.__connect_timeout)

            self.__socket.connect((self.ip, self.port))

            if self.__protocol == socket.SOCK_STREAM:
                self.__socket.settimeout(None)

            logging.info(
                f"Сокет успешно создан {self.__socket.getsockname()} ←→ {self.__socket.getpeername()}"
            )
        except BaseException as e:
            msg = self.__format_socket_error(e)
            logging.error(f"Не удалось создать/подключить сокет: {msg}")
            raise DeviceError(
                f"Не удалось подключиться к устройству {self.ip}:{self.port}. {msg}"
            ) from e

    # --------- Генераторы команд ---------

    def __file_creation_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.FILE_CREATION_COMMAND_CODE + self.__password
        )
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __file_creation_status_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.FILE_CREATION_STATUS_COMMAND_CODE
            + self.__password
        )
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __hash_calculating_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.HASH_CALCULATING_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __hash_calculating_status_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.HASH_CALCULATING_STATUS_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __file_transfer_init_request_gen(self) -> bytes:
        payload = (
            Scales.Codes.JsonFileReceiving.HASH_CALCULATING_COMMAND_CODE
            + self.__password
            + Scales.Codes.JsonFileReceiving.FILE_RECEIVING_INITIATION_STAGE_CODE
        )
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    # --------- Send/Recv ---------

    def __send(self, data: bytes, label: str, bigdata: bool = False) -> None:
        try:
            if self.__protocol == socket.SOCK_STREAM:
                self.__socket.sendall(data)
                if not bigdata:
                    logging.debug(
                        f"[>] На весы TCP {self.__socket.getsockname()} ←→ {self.__socket.getpeername()} "
                        f"{label} | {len(data)} байт | HEX: {data.hex()} | {data}"
                    )
                else:
                    logging.debug(
                        f"[>] На весы TCP {self.__socket.getsockname()} ←→ {self.__socket.getpeername()} "
                        f"{label} | {len(data)} байт | {list(data[:17])}"
                    )
            else:
                raise  DeviceError("Протокол UDP не поддерживается.")
        except BaseException as e:
            msg = self.__format_socket_error(e)
            logging.error(f"Ошибка отправки ({label}): {msg}")
            if (
                self.__auto_reconnect
                and self.__protocol == socket.SOCK_STREAM
                and self.__is_transient_socket_error(e)
            ):
                try:
                    self.__reconnect()
                except Exception:
                    pass
            raise DeviceError(
                f"Не удалось отправить данные на устройство. {msg}"
            ) from e

    def __recv(
        self,
        bufsize: int = 2048,
        timeout: Optional[float] = None,
        bigdata: bool = False,
    ) -> Optional[bytes]:
        if timeout is None:
            timeout = self.__default_timeout

        self.__socket.settimeout(timeout)

        try:
            if self.__protocol == socket.SOCK_STREAM:
                data = self.__recv_tcp_frame(timeout)
                if not data:
                    return None

                if not bigdata:
                    logging.debug(
                        f"[<] От весов TCP {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} "
                        f"| {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
                    )
                else:
                    logging.debug(
                        f"[<] От весов TCP {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} "
                        f"| {len(data)} байт | {list(data[:17])}"
                    )
                return data
            else:
                raise DeviceError("Протокол UDP не поддерживается.")

        except socket.timeout:
            logging.warning(
                "Не удалось получить ответ от весов за отведенное время (timeout)."
            )
            return None

        except BaseException as e:
            msg = self.__format_socket_error(e)
            logging.error(f"Ошибка приема данных: {msg}")

            if (
                self.__auto_reconnect
                and self.__protocol == socket.SOCK_STREAM
                and self.__is_transient_socket_error(e)
            ):
                try:
                    self.__reconnect()
                except Exception:
                    pass

            raise DeviceError(
                f"Устройство не отвечает или соединение разорвано. {msg}"
            ) from e

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
            try:
                chunk = self.__socket.recv(n - received)
            except socket.timeout:
                raise
            except BaseException as e:
                raise

            if not chunk:
                raise ConnectionResetError(
                    "TCP соединение закрыто удаленной стороной (recv вернул 0 байт)."
                )

            chunks.append(chunk)
            received += len(chunk)

        return b"".join(chunks)

    def __transceive(
        self,
        data: bytes,
        label: str,
        *,
        recv_bufsize: int = 2048,
        timeout: Optional[float] = None,
        bigdata: bool = False,
        retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ) -> bytes:
        """
        Send + recv с повторными попытками при отсутствии ответа и
        с понятной ошибкой, если устройство не отвечает.
        """
        if retries is None:
            retries = self.__retries
        if retry_delay is None:
            retry_delay = self.__retry_delay

        last_timeout = False

        for attempt in range(retries + 1):
            self.__send(data, label, bigdata=bigdata)
            resp = self.__recv(recv_bufsize, timeout=timeout, bigdata=bigdata)
            if resp is not None:
                return resp

            last_timeout = True
            if attempt < retries:
                logging.warning(
                    f"Нет ответа от устройства (attempt {attempt + 1}/{retries + 1}). Повтор через {retry_delay} сек."
                )
                time.sleep(retry_delay)

                # Для TCP переподкл
                if self.__auto_reconnect and self.__protocol == socket.SOCK_STREAM:
                    try:
                        self.__reconnect()
                    except Exception:
                        pass

        if last_timeout:
            raise DeviceError(
                f"Устройство не отвечает: истек таймаут ожидания ответа после {retries + 1} попыток. Команда: {label}."
            )

        raise DeviceError(f"Устройство не отвечает. Команда: {label}.")

    # --------- Валидация ответа ---------

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
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине."
                )
        elif cond == "gt":
            if not (len(response) > length):
                raise DeviceError(
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине."
                )
        elif cond == "lt":
            if not (len(response) < length):
                raise DeviceError(
                    f"Ответ от весов не соответствует ожидаемой согласно протоколу длине."
                )

    # --------- Публичные методы ---------

    def get_products_json(self) -> dict:
        logging.info(
            f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} инициирован процесс получения JSON списка товаров."
        )

        scales_response = self.__transceive(
            self.__file_creation_request_gen(),
            "Пакет с запросом на создание файла",
        )
        self.__response_validator(scales_response, length=5)

        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")

        while True:
            scales_response = self.__transceive(
                self.__file_creation_status_request_gen(),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            self.__response_validator(scales_response, length=5)
            if scales_response[4] == Scales.Codes.ResponseCodes.IN_PROGRESS:
                continue
            else:
                break

        scales_response = self.__transceive(
            self.__hash_calculating_request_gen(),
            "Пакет с запросом на начало расчёта хэш-данных",
        )
        self.__response_validator(scales_response, length=5)
        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")

        file_hash: bytes = b""
        time.sleep(1)

        scales_response = self.__transceive(
            self.__hash_calculating_status_request_gen(),
            "Пакет с запросом на получение статуса расчёта хэш-данных",
            recv_bufsize=2048,
            timeout=self.__default_timeout,
        )
        self.__response_validator(scales_response, length=22)
        if scales_response[4] == Scales.Codes.ResponseCodes.SUCCESS:
            pass
            # file_hash = scales_response[10:26]
        else:
            raise DeviceError("Ответ весов не удовлетворяет условиям.")

        file_data = bytearray()
        while True:
            _ = self.__send(
                self.__file_transfer_init_request_gen(),
                "Пакет с запросом на получение порции файла",
            )
            time.sleep(0.3)

            data = self.__recv(65507, timeout=10, bigdata=True)
            if data is None:
                raise DeviceError(
                    "Устройство не отвечает: порция файла не получена (timeout)."
                )

            self.__response_validator(data, length=12, cond="gt")
            try:
                is_last_chunk = data[5] == 1  # флаг последней порции
                file_data.extend(data[12:])
            except IndexError:
                raise DeviceError("Ошибка при получении порции файла.")
            if is_last_chunk:
                break

        try:
            json_data = get_json_from_bytearray(file_data)
            if json_data is None:
                raise DeviceError(
                    "Не удалось распознать JSON от весов (получено None)."
                )
            logging.info(
                f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} данные товаров в формате JSON получены."
            )
            return json_data

        except JSONDecodeError as e:
            logging.exception("Некорректный JSON от весов")
            raise DeviceError(f"Некорректный JSON от весов: {e}") from e

    def __initial_file_transfer_request_gen(
        self, data: bytes, clear_database: bool = False
    ) -> bytes:
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
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    def __file_transfer_commands_gen(
        self,
        data: bytes,
    ) -> Tuple[bytes, ...]:
        command = bytes([0xFF, 0x13])
        chunk_sending_code = bytes([0x03])
        offset_param = 0
        total_len = len(data)
        packets = []

        while offset_param < total_len:
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
                Scales.__tcp_command_len_generator(package, self.command_len_bytes)
                + package
            )

            offset_param += self.__file_chunk_limit

        return tuple(packets)

    def __transfered_file_check_command_gen(self):
        command = bytes([0xFF, 0x13])
        file_check_code = bytes([0x09])
        payload = command + self.__password + file_check_code
        package = self.__packet_header_gen(payload) + payload
        return (
                Scales.__tcp_command_len_generator(package, self.command_len_bytes) + package
        )

    @staticmethod
    def __packet_header_gen(payload: bytes):
        if len(payload) < 255:
            return Scales.Codes.Global.STX + bytes([len(payload)])
        else:
            return (
                Scales.Codes.Global.STX + Scales.Codes.Global.UNLIMITED_PACKET_SIZE_CODE
            )

    @staticmethod
    def __tcp_command_len_generator(package: bytes, length: int) -> bytes:
        return len(package).to_bytes(length, byteorder="little", signed=False)

    def send_json_products(self, data: dict) -> None:
        logging.info(
            f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} инициирован процесс отправки JSON списка товаров."
        )

        json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )

        scales_response = self.__transceive(
            self.__initial_file_transfer_request_gen(json_bytes, clear_database=True),
            "Пакет, содержащий хэш-данные файла и параметры",
        )
        self.__response_validator(scales_response, length=5)
        if scales_response[4] != Scales.Codes.ResponseCodes.SUCCESS:
            raise DeviceError(
                "Не удалось инициализировать передачу JSON файла на весы. "
                "Ошибка на этапе передачи хэш-данных файла и параметров."
            )

        packets = self.__file_transfer_commands_gen(json_bytes)
        for packet in packets:
            scales_response = self.__transceive(
                packet,
                "Пакет, содержащий порцию файла",
                bigdata=True,
                timeout=self.__default_timeout,
            )
            self.__response_validator(scales_response, length=5)
            if scales_response[4] == Scales.Codes.ResponseCodes.SUCCESS:
                continue
            else:
                raise DeviceError(
                    "Попытка загрузить порцию файла завершилась неудачей."
                )

        while True:
            scales_response = self.__transceive(
                self.__transfered_file_check_command_gen(),
                "Пакет с запросом на проверку отправляемого файла",
                timeout=self.__default_timeout,
            )
            self.__response_validator(scales_response, length=8)
            if scales_response[5] == Scales.Codes.ResponseCodes.IN_PROGRESS_FILE:
                time.sleep(1)
                logging.info(
                    f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} файл еще находится на стадии проверки устройством."
                )
                continue
            elif scales_response[5] == Scales.Codes.ResponseCodes.SUCCESS:
                logging.info(
                    f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} файл успешно обработан устройством."
                )
                break
            elif scales_response[5] == Scales.Codes.ResponseCodes.ERROR_FILE:
                raise DeviceError(
                    f"[!] Сокет {self.__socket.getpeername()} ←→ {self.__socket.getsockname()} файл обработан с ошибкой. Загрузка не удалась."
                )


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
