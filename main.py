import logging
import datetime
from json import JSONDecodeError
from pprint import pprint

from scales import Scales, DeviceError
from settings import SCALE_IP, SCALE_PORT, SCALE_PASSWORD
from datetime import datetime, timedelta


def update_dates(product: dict) -> dict:
    today = datetime.now()
    shelf_life_days = product.get("shelfLifeInDays", 0)
    date_format = "%d-%m-%y"
    product["manufactureDate"] = today.strftime(date_format)
    product["sellByDate"] = (today + timedelta(days=shelf_life_days)).strftime(
        date_format
    )
    return product


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    scales = Scales(SCALE_IP, SCALE_PORT, SCALE_PASSWORD, "TCP")
    try:
        products = scales.get_products_json()
    except JSONDecodeError as e:
        logging.error(f"{e}")
    except DeviceError as e:
        logging.error(f"{e}")
    except IndexError as e:
        logging.error(f"{e}")
    # pprint(products)
    for product in products["products"]:
        product = update_dates(product)
    # pprint(products)
    scales.send_json_products(products)
