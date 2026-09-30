ELIDED_TAGS = [
    "X509Certificate",
    "SignatureValue",
    "DigestValue",
    "CipherValue"
]

def tag_name(tag: str, include_namespace: bool = True) -> str:
    name = ""
    start = 0
    if tag[start] == "<":
        start += 1
        if tag[start] == "/":
            start += 1
    for char in tag[start:]:
        if char in " \n/>":
            break
        name += char
    if not include_namespace:
        name = name.split(":")[-1]
    return name

def pretty_print_xml(xml: str):
    if isinstance(xml, bytes):
        xml = str(xml, "utf-8")

    tag_groups = {}
    tags = []
    tag = ""
    closed = False
    istag = True
    for char in xml:
        if char == "\n":
            continue
        if tag == "" and char != "<":
            istag = False
        if not istag and char == "<":
            tags.append(tag)
            tag = ""
            istag = True
        tag += char
        if char == ">":
            tag_groups[tag_name(tag)] = closed
            tags.append(tag)
            tag = ""
            closed = False
            continue
        if tag == "</":
            closed = True
            continue

    space_count = 0
    prev = ""
    for tag in tags:
        istag = tag.startswith("<")
        closing = istag and tag[1] == "/"
        if closing and tag_groups[tag_name(tag)]:
            space_count -= 4
        if istag and prev.startswith("<"): # istag and prev_istag
            print("\n" + (" " * space_count), end="")
        print(tag if (istag or tag_name(prev).split(":")[-1] not in ELIDED_TAGS) else "...", end="")
        if istag and tag_groups[tag_name(tag)] and not closing:
            space_count += 4
        prev = tag
    print()
