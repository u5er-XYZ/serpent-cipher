
phi = 0x9e3779b9
num_rounds = 32

Initial_Permutation_Table = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
]


Final_Permutation_Table = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
]

# SBoxDecimalTable = [
#     [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],  
#     [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],  
#     [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],  
#     [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],  
#     [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],  
#     [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],  
#     [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],  
#     [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],  
# ]


def hexadecimal_to_binary(hex):
    return ''.join(['{:04b}'.format(int(i, 16)) for i in hex])  


def binary_to_hexadecimal(bin):
    return ''.join(['{:x}'.format(int(bin[i:i + 4], 2)) for i in range(0, len(bin), 4)])


def hex_string_to_binary(n, minlen):
    bits = hexadecimal_to_binary(n)
    bits += '0' * (minlen - len(bits))
    return bits

def string2binary(text):
    return ''.join(['{:08b}'.format(ord(char)) for char in text])

def padding_key_256(key):
    if len(key) < 256:
        key += '1'
    return key + '0' * (256 - len(key))


def rotateLeft(word, shift):
    shift = shift % len(word)
    return word[-shift:] + word[:-shift]

def rotateRight(word,shift):
    shift = shift % len(word)
    return rotateLeft(word,-shift)




def xor(*args):
    def xor_1by1(x,y):
        return ''.join([str(int(i)^int(j)) for i, j in zip(x,y)])
    res = args[0]
    for i in range(1,len(args)):
        res=xor_1by1(res,args[i])
    return res



def bitstring(inp, minlen=1):

    binary_str = format(inp, 'b')
    if len(binary_str) < minlen:
        binary_str = '0' * (minlen - len(binary_str)) + binary_str

    return binary_str




# sbox_string = []
# inverse_sbox_string = []
# for box in SBoxDecimalTable:
#     Dict = {}
#     InverseDict = {}
#     for i in range(len(box)):
#         ind = bitstring(i, 4)
#         val = bitstring(box[i], 4)
#         Dict[ind] = val
#         InverseDict[val] = ind
#     sbox_string.append(Dict)
#     inverse_sbox_string.append(InverseDict)

sbox_string=[{'0000': '0011', '0001': '1000', '0010': '1111', '0011': '0001', '0100': '1010', '0101': '0110', '0110': '0101', '0111': '1011', '1000': '1110', '1001': '1101', '1010': '0100', '1011': '0010', '1100': '0111', '1101': '0000', '1110': '1001', '1111': '1100'}, {'0000': '1111', '0001': '1100', '0010': '0010', '0011': '0111', '0100': '1001', '0101': '0000', '0110': '0101', '0111': '1010', '1000': '0001', '1001': '1011', '1010': '1110', '1011': '1000', '1100': '0110', '1101': '1101', '1110': '0011', '1111': '0100'}, {'0000': '1000', '0001': '0110', '0010': '0111', '0011': '1001', '0100': '0011', '0101': '1100', '0110': '1010', '0111': '1111', '1000': '1101', '1001': '0001', '1010': '1110', '1011': '0100', '1100': '0000', '1101': '1011', '1110': '0101', '1111': '0010'}, {'0000': '0000', '0001': '1111', '0010': '1011', '0011': '1000', '0100': '1100', '0101': '1001', '0110': '0110', '0111': '0011', '1000': '1101', '1001': '0001', '1010': '0010', '1011': '0100', '1100': '1010', '1101': '0111', '1110': '0101', '1111': '1110'}, {'0000': '0001', '0001': '1111', '0010': '1000', '0011': '0011', '0100': '1100', '0101': '0000', '0110': '1011', '0111': '0110', '1000': '0010', '1001': '0101', '1010': '0100', '1011': '1010', '1100': '1001', '1101': '1110', '1110': '0111', '1111': '1101'}, {'0000': '1111', '0001': '0101', '0010': '0010', '0011': '1011', '0100': '0100', '0101': '1010', '0110': '1001', '0111': '1100', '1000': '0000', '1001': '0011', '1010': '1110', '1011': '1000', '1100': '1101', '1101': '0110', '1110': '0111', '1111': '0001'}, {'0000': '0111', '0001': '0010', '0010': '1100', '0011': '0101', '0100': '1000', '0101': '0100', '0110': '0110', '0111': '1011', '1000': '1110', '1001': '1001', '1010': '0001', '1011': '1111', '1100': '1101', '1101': '0011', '1110': '1010', '1111': '0000'}, {'0000': '0001', '0001': '1101', '0010': '1111', '0011': '0000', '0100': '1110', '0101': '1000', '0110': '0010', '0111': '1011', '1000': '0111', '1001': '0100', '1010': '1100', '1011': '1010', '1100': '1001', '1101': '0011', '1110': '0101', '1111': '0110'}]
inverse_sbox_string=[{'0011': '0000', '1000': '0001', '1111': '0010', '0001': '0011', '1010': '0100', '0110': '0101', '0101': '0110', '1011': '0111', '1110': '1000', '1101': '1001', '0100': '1010', '0010': '1011', '0111': '1100', '0000': '1101', '1001': '1110', '1100': '1111'}, {'1111': '0000', '1100': '0001', '0010': '0010', '0111': '0011', '1001': '0100', '0000': '0101', '0101': '0110', '1010': '0111', '0001': '1000', '1011': '1001', '1110': '1010', '1000': '1011', '0110': '1100', '1101': '1101', '0011': '1110', '0100': '1111'}, {'1000': '0000', '0110': '0001', '0111': '0010', '1001': '0011', '0011': '0100', '1100': '0101', '1010': '0110', '1111': '0111', '1101': '1000', '0001': '1001', '1110': '1010', '0100': '1011', '0000': '1100', '1011': '1101', '0101': '1110', '0010': '1111'}, {'0000': '0000', '1111': '0001', '1011': '0010', '1000': '0011', '1100': '0100', '1001': '0101', '0110': '0110', '0011': '0111', '1101': '1000', '0001': '1001', '0010': '1010', '0100': '1011', '1010': '1100', '0111': '1101', '0101': '1110', '1110': '1111'}, {'0001': '0000', '1111': '0001', '1000': '0010', '0011': '0011', '1100': '0100', '0000': '0101', '1011': '0110', '0110': '0111', '0010': '1000', '0101': '1001', '0100': '1010', '1010': '1011', '1001': '1100', '1110': '1101', '0111': '1110', '1101': '1111'}, {'1111': '0000', '0101': '0001', '0010': '0010', '1011': '0011', '0100': '0100', '1010': '0101', '1001': '0110', '1100': '0111', '0000': '1000', '0011': '1001', '1110': '1010', '1000': '1011', '1101': '1100', '0110': '1101', '0111': '1110', '0001': '1111'}, {'0111': '0000', '0010': '0001', '1100': '0010', '0101': '0011', '1000': '0100', '0100': '0101', '0110': '0110', '1011': '0111', '1110': '1000', '1001': '1001', '0001': '1010', '1111': '1011', '1101': '1100', '0011': '1101', '1010': '1110', '0000': '1111'}, {'0001': '0000', '1101': '0001', '1111': '0010', '0000': '0011', '1110': '0100', '1000': '0101', '0010': '0110', '1011': '0111', '0111': '1000', '0100': '1001', '1100': '1010', '1010': '1011', '1001': '1100', '0011': '1101', '0101': '1110', '0110': '1111'}]

def Substitute(box, inp, inverse=False):
    box=box%8
    if inverse==True:
        return inverse_sbox_string[box][inp]
    else:
        return sbox_string[box][inp]




def Permutation(inp, initial=True):
    if initial==True:
        return ''.join([inp[Initial_Permutation_Table[i]] for i in range(128)])
    else:
        return ''.join([inp[Final_Permutation_Table[i]] for i in range(128)])


def create_prekeys(key):
    w = {}
    for i in range(-8, 0):
        w[i] = key[(i + 8) * 32:(i + 9) * 32]

    # PREKEY GENERATION
    for i in range(132):
        t=xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1], bitstring(phi, 32), bitstring(i, 32))
        w[i] = rotateLeft(t, 11)
    return w


def create_subkeys(key):
    w=create_prekeys(key)
    # GROUPED ROUND KEYS GENERATION
    K = []
    for i in range(num_rounds + 1):

        s_box_num = (num_rounds + 3 - i) % num_rounds
        temp = ['', '', '', '']
        for a, b, c, d in zip(w[(4*i)], w[(4*i) + 1], w[(4*i) + 2], w[(4*i) + 3]):
            before_sbox = a + b + c + d
            op = list(Substitute(s_box_num, before_sbox))  
            temp = [x + y for x, y in zip(temp, op)]  
        K.append(''.join(temp))  

    Keys = [Permutation(i) for i in K]
    return Keys

def shiftLeft(input, s):

    if abs(s) >= len(input):
   
        return "0" * len(input)
    if s < 0:
        return  input[-s:] + "0" * len(input[:-s])
    elif s == 0:
        return input
    else: 
        return "0" * len(input[-s:]) + input[:-s]

def LinearTransformation(input_bytes):

    w=[input_bytes[i:i+32] for i in range(0,128,32)]
    w[0] = rotateLeft(w[0], 13)
    w[2] = rotateLeft(w[2], 3)
    w[1] = xor(w[1], w[0], w[2])
    w[3] = xor(w[3], w[2], shiftLeft(w[0], 3))
    w[1] = rotateLeft(w[1], 1)
    w[3] = rotateLeft(w[3], 7)
    w[0] = xor(w[0], w[1], w[3])
    w[2] = xor(w[2], w[3], shiftLeft(w[1], 7))
    w[0] = rotateLeft(w[0], 5)
    w[2] = rotateLeft(w[2], 22)

    return ''.join(w)




def InverseLinearTransformation(input_bytes):

    w=[input_bytes[i:i+32] for i in range(0,128,32)]
    w[2] = rotateRight(w[2], 22)
    w[0] = rotateRight(w[0], 5)
    w[2] = xor(w[2], w[3], shiftLeft(w[1], 7))
    w[0] = xor(w[0], w[1], w[3])
    w[3] = rotateRight(w[3], 7)
    w[1] = rotateRight(w[1], 1)
    w[3] = xor(w[3], w[2], shiftLeft(w[0], 3))
    w[1] = xor(w[1], w[0], w[2])
    w[2] = rotateRight(w[2], 3)
    w[0] = rotateRight(w[0], 13)
    return ''.join(w)


def Round(i, intermediate_text, Keys):
    xored_text = xor(intermediate_text, Keys[i])
    substituted_text = ''.join([Substitute(i, xored_text[ind:ind + 4]) for ind in range(0, len(xored_text), 4)])

    if i>=0 and i <= num_rounds - 2:
        intermediate = LinearTransformation(substituted_text)
    else:
        intermediate = xor(substituted_text, Keys[num_rounds])

    return intermediate


def inverseRound(i, intermediate, Keys):

    if i>=0 and i <= num_rounds - 2:
        before_sbox = InverseLinearTransformation(intermediate)
    else:
        before_sbox = xor(intermediate, Keys[num_rounds])


    before_xor = ''.join([Substitute(i, before_sbox[ind:ind + 4],True) for ind in range(0, len(before_sbox), 4)])

    output = xor(before_xor, Keys[i])
    return output



def encrypt(text, key):
    bin_text = string2binary(text)

    Keys = create_subkeys(key)

    intermediate_text = Permutation(bin_text)
    for i in range(num_rounds):
        intermediate_text = Round(i, intermediate_text, Keys)
    cipher = Permutation(intermediate_text,initial=False)

    cipher = binary_to_hexadecimal(cipher)
    return cipher

def decrypt(cipher, key):
    binary_cipher = hexadecimal_to_binary(cipher)

    Keys = create_subkeys(key)

    intermediate_cipher = Permutation(binary_cipher)
    for i in range(num_rounds - 1, -1, -1):
        intermediate_cipher = inverseRound(i, intermediate_cipher, Keys)
    plaintext = Permutation(intermediate_cipher,initial=False)

    plaintext = ''.join([chr(int(plaintext[i:i+8], 2)) for i in range(0, len(plaintext), 8)])
    return plaintext




def main():
    c='e'
    while(c!='o'):
        print("Press e to encrypt")
        print("Press i to change plaintext")
        print("Press d to decrypt")
        print("Press k to change key")
        print("Press v to view cipher text,key and plain text")
        print("Press o to exit")
        c=input().lower()
        key=''
        with open('key.txt', 'r') as input_file:
                key = input_file.read()
        # key='1A2B3C4D5E6F78911A2B3C4D5E6F7891'
        bin_key = hex_string_to_binary(key, len(key) * 4)
        assert len(bin_key) % 32 == 0 and 64 <= len(bin_key) <= 256, 'Invalid key length, Enter hex key with length in multiples of 16 and in range(16, 64) hex digits.'
        padded_key = padding_key_256(bin_key)

        if c=='e':
            with open('plaintext.txt', 'r') as input_file:
                message = input_file.read()
            message_blocks = [message[i:i+16] for i in range(0, len(message), 16)]
            if len(message_blocks[-1]) < 16:
                message_blocks[-1] += ' '*(16 - len(message_blocks[-1]))


            cipher = ''.join([encrypt(block, padded_key) for block in message_blocks])
            with open('ciphertext.txt', 'w') as output_file:
                output_file.write(cipher)
            print('Cipher text:', cipher)
        elif c=='d':
            with open('ciphertext.txt', 'r') as input_file:
                cipher = input_file.read()
            cipher_blocks = [cipher[i:i+32] for i in range(0, len(cipher), 32)]
            assert len(cipher)%32 == 0, 'length of cipher does not match'

            plaintext = ''.join([decrypt(block, padded_key) for block in cipher_blocks]).strip()
            print('Plaintext:', plaintext)
        elif c=='k':
            print("Please input hexadecimal key between 128 to 256 bit length")
            key=input()
            with open('key.txt', 'w') as output_file:
                output_file.write(key)
        elif c=='v':
            with open('plaintext.txt', 'r') as input_file:
                message = input_file.read()
            with open('ciphertext.txt', 'r') as input_file:
                cipher = input_file.read()
            with open('key.txt', 'r') as input_file:
                key = input_file.read()
            print('Cipher text:', cipher)
            print('Plaintext:', message)
            print("Key:",key)
        elif c=='i':
            plaintext=input()
            with open('plaintext.txt', 'w') as output_file:
                output_file.write(plaintext)
        elif c=='o'or c=='0':
            break
        else:
            print("Please enter the correct option")
        print("Press Enter to continue...")
        input()
            

if __name__=="__main__":
    main()



        
