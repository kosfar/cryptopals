#!/usr/bin/env python

import logging
import base64
import string

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def hex_to_bytes(s):
    """
    :type s: str
    :rtype: bytearray
    """
    return bytearray.fromhex(s)

def bytes_to_base64(s):
    """
    :type s: bytearray
    :rtype: str
    """
    logger.debug('{}'.format(type(base64.b64encode(s))))
    return base64.b64encode(s)

def hex_to_base64(s):
    """
    :type s: str
    :rtype: str
    Convert hex to base64.
    """
    b = hex_to_bytes(s)
    return bytes_to_base64(b)

def bytes_to_hex(s):
    """
    Convert bytes to hex.
    """

    return s.encode("hex")

def xor_hex(s1, s2):
    """
    Calculate the XOR combination from two equal-length buffers.
    :type s1: str
    :type s2: str
    :rtype: str
    """

    # TODO: What about non equal strings? Isn't XOR valid?
    if len(s1) != len(s2):
        raise Exception("Strings are not of the same length")

    r1 = hex_to_bytes(s1)
    r2 = hex_to_bytes(s2)

    result = ''
    for x,y in zip(r1,r2):
        result += chr(x ^ y)

    return bytes_to_hex(result)

def score(text):
    # Taken from wikipedia
    score_card = {
        'e': 12.70,
        't': 9.06,
        'a': 8.17,
        'o': 7.51,
        'i': 6.97,
        'n': 6.75,
        's': 6.33,
        'h': 6.09,
        'r': 5.99,
        'd': 4.25,
        'l': 4.03,
        'c': 2.78,
        'u': 2.76,
        'm': 2.41,
        'w': 2.36,
        'f': 2.23,
        'g': 2.02,
        'y': 1.97,
        'p': 1.93,
        'b': 1.29,
        'v': 0.98,
        'k': 0.77,
        'j': 0.15,
        'x': 0.15,
        'q': 0.10,
        'z': 0.07
    }
    s = 0

    for c in text:
        if c in score_card:
            s = s + score_card[c]
        elif c not in string.printable:
            s = 0
            break
        else:
            s = s + 0.01
    return s

def decipher_single_char_xored(cipher_text):
    """
    One hexadecimal digit represents a nibble (4 bits). A single byte is 2 hex digits ie FF, 00
    Extended ASCII is an 8-bit character set. 2^8 equals 256, and as counting starts with 0,
    the maximum ASCII char code has the value 255.
    """
    best_score = 0
    p = ''
    key = -1
    for i in range(0,256):
        c = xor_hex(cipher_text,(chr(i) * (len(cipher_text) / 2)).encode('hex'))
        if score(c.decode('hex')) > best_score:
            best_score = score(c.decode('hex'))
            p = c.decode('hex').strip('\n')
            key = i

    return (p, key, best_score)

def main():
    #s1c1
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    r = hex_to_base64(s)
    if r == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t":
        print "Set 1 - Challenge 1: Unlocked! :)"
    else:
        print "Set 1 - Challenge 1: ZoOong!!!!"

    #s1c2
    r = xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    if r == "746865206b696420646f6e277420706c6179":
        print "Set 1 - Challenge 2: Unlocked! :)"
    else:
        print "Set 1 - Challenge 2: ZoOong!!!!"

    #s1c3
    rtup = decipher_single_char_xored('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    if rtup[2] > 0:
        logger.info("Set 1 - Challenge 3: Plaintext: {}. Key: {} ('{}'). Woohoo!".format(rtup[0],rtup[1], chr(rtup[1])))

    #s1c4
    arr = []
    with open('s1c4.txt', 'r') as f:
        for line in f:
            rtup = decipher_single_char_xored(line.strip('\n'))
            arr.append(rtup)

    arr_by_score = sorted(arr, key=lambda tup: tup[2], reverse = True)
    winner_tup = arr_by_score[0]
    if winner_tup[2] > 0:
        logger.info("Set 1 - Challenge 4: Plaintext: {}. Key: {} ('{}'). Woohoo!".format(winner_tup[0],winner_tup[1], chr(winner_tup[1])))

if __name__ == "__main__":
	main()