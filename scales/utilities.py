import json
import logging


def get_json_from_bytearray(data: bytes) -> dict | None:
    """
    Преобразует байтовую строку в JSON-словарь.
    Если получен список, он будет обёрнут в словарь под ключом 'items'.

    :param data: Байтовые данные, содержащие JSON.
    :return: Словарь JSON или None в случае ошибки.
    """
    try:
        json_str = data.decode("utf-8")
        parsed = json.loads(json_str)

        if isinstance(parsed, dict):
            result = parsed
        elif isinstance(parsed, list):
            result = {"items": parsed}
        else:
            print("Получен неизвестный тип JSON:", type(parsed))
            return None
        return result

    except Exception as e:
        logging.error("Ошибка декодирования JSON:", e)
        return None
