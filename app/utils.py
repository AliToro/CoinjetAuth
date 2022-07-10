import logging

import phonenumbers as ph
import re

from fastapi import HTTPException
from starlette import status


def check_phone_num(phone_num_str):
    if re.match('\+?[0-9]+', phone_num_str) is None:
        return False
    try:
        validated_phone_num = ph.parse(phone_num_str, "IR")
    except Exception as ex:
        return False
    if ph.is_possible_number(validated_phone_num) and ph.is_valid_number(validated_phone_num):
        return True
    else:
        return False

def normalize_phone_num(phone_num_str):
    if check_phone_num(phone_num_str):
        normalized_phone_num = ph.format_number(ph.parse(phone_num_str, "IR"), ph.PhoneNumberFormat.E164)
        logging.info("The {} is valid and normalized version is '{}'".format(phone_num_str, normalized_phone_num))
        return normalized_phone_num
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The {} is not a valid phone number.".format(phone_num_str))

def test_check_num():
    phone_nums = ["00989123332244", "+989123332244", "989123332244", "09123332244", "9123332244", "912333224",
                  "91233322", "+9891233322", "0912333224", "'0912333224'", "091233322", "a989123332244", "a9123332244",
                  "a91233322bb", "a912XE@2244", "abbcc", "+98ab", "091233322bb", "912", "0912", "+98", "009891"]

    for phone_num in phone_nums:
        phone_check_res = check_num(phone_num)
        if phone_check_res[0]:
            print("The {:15s} is valid and normalized version is '{}'".format(phone_num, phone_check_res[1]))
        else:
            print("The {:15s} is not valid.".format(phone_num))