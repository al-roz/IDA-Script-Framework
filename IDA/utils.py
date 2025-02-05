import idc



def is_str(addr):
    ASCSTR = ["C", "Pascal", "LEN2", "Unicode", "LEN4", "ULEN2", "ULEN4"]
    str_type = idc.get_str_type(addr)
    if str_type is None:
        return False
    if 0 < str_type:
        return False
    else:
        return True


def replace_incorrect_symbols_in_name(name):
    incorrect_symbols = '-,.<>[]~@$^%&*()'
    replacement_char = '_'

    result = name

    if name:
        for symbol in incorrect_symbols:
            result = result.replace(symbol, replacement_char)

    return result
