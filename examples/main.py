import logging
import pprint
from json import JSONDecodeError
from datetime import datetime, timedelta

from scales import Scales, DeviceError
from settings import SCALE_IP, SCALE_PORT, SCALE_PASSWORD


def update_dates(product: dict) -> dict:
    today = datetime.now()
    shelf_life_days = product.get("shelfLifeInDays", 0)
    date_format = "%d-%m-%y"
    product["manufactureDate"] = today.strftime(date_format)
    product["sellByDate"] = (today + timedelta(days=shelf_life_days)).strftime(
        date_format
    )
    return product


def run_products_update_once() -> None:
    scales = Scales(
        SCALE_IP,
        SCALE_PORT,
        SCALE_PASSWORD,
        "TCP",
        auto_reconnect=True,
        # connect_timeout=3.0,
        # default_timeout=5.0,
        # retries=2,
        # retry_delay=0.5,
    )

    products = scales.get_products_json()

    for i, product in enumerate(products.get("products", [])):
        products["products"][i] = update_dates(product)
    # pprint.pprint(products)
    scales.send_json_products(products)


def run_products_update(attempts: int = 2) -> None:
    for attempt in range(1, attempts + 1):
        try:
            run_products_update_once()
            logging.info("Обновление товаров завершено успешно.")
            break

        except DeviceError as e:

            logging.error("Ошибка обмена с весами: %s", e)

            if attempt < attempts:
                logging.warning("Повтор полной операции...")

                continue
            logging.error(
                f"Весы недоступны после %d попыток. Итерация завершена.", attempts
            )
            return

        except JSONDecodeError as e:
            logging.error(f"Получены некорректные данные от весов (JSON): {e}")
            raise

        except Exception as e:
            logging.exception(f"Непредвиденная ошибка: {e}")
            raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_products_update(attempts=2)
