ELIDED_TAGS = [
    "X509Certificate",
    "SignatureValue",
    "DigestValue",
    "CipherValue"
]

def tag_name(tag: str) -> str:
    if tag.startswith("..."):
        tag = tag[3:]
    name = ""
    for char in tag:
        if char in "</":
            continue
        if char in " \n/>":
            break
        name += char
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

    first = True
    space_count = 0
    prev = ""
    for tag in tags:
        istag = tag.startswith("<")
        closing = istag and tag[1] == "/"
        if istag and prev.startswith("<") and not first:
            print()
        if closing: space_count -= 4
        if istag and prev.startswith("<"): print(" " * space_count, end="")
        print(tag if istag or tag_name(prev).split(":")[-1] not in ELIDED_TAGS else "...", end="")
        if istag and tag_groups[tag_name(tag)] and not closing: space_count += 4
        prev = tag
        first = False
    print()
