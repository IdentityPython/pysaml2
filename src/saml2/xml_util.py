import xml.etree.ElementTree as ET


def replace_retrieval_method(xmlstr):
    """
    Given an XML string, replace entries of RetrievalMethod with the referred
    content. Used to support EncryptedKey retrieval method for KeyInfo in
    encrypted assertions.
    """
    root = ET.fromstring(xmlstr)
    ds_ns = 'http://www.w3.org/2000/09/xmldsig#'
    xenc_ns = 'http://www.w3.org/2001/04/xmlenc#'
    retrieval_methods = root.findall('.//{{{}}}RetrievalMethod'.format(ds_ns))
    replacements = []
    for retmet in retrieval_methods:
        if (retmet.attrib['Type'] !=
                'http://www.w3.org/2001/04/xmlenc#EncryptedKey'):
            # Unsupported
            continue
        uri = retmet.attrib['URI']
        if not uri.startswith('#'):
            # Unsupported
            continue
        encrypted_key = \
            root.findall(
                './/{{{}}}EncryptedKey[@Id="{}"]'.format(xenc_ns, uri[1:]))
        if len(encrypted_key) != 1:
            # Unsupported
            continue
        replacements.append((retmet, encrypted_key[0]))

    parent_map = {c: p for p in root.iter() for c in p}
    for old, new in replacements:
        parent = parent_map[old]
        parent_index = list(parent).index(old)
        parent.remove(old)
        parent.insert(parent_index, new)
    # now remove the referenced keys from the original position
    for _, new in replacements:
        parent = parent_map[new]
        parent.remove(new)
    return ET.tostring(root)
