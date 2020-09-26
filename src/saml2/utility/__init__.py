def make_type(mtype, *args):
    t_args = []
    similar_type = tuple if mtype is list else list
    for x in args:
        t_args.extend([x] if not isinstance(x, (list, tuple)) else similar_type(x))
    return mtype(t_args)


def make_list(*args):
    return make_type(list, *args)


def not_empty(element):
    if isinstance(element, bool):
        return True

    if element:
        return True
    return False
