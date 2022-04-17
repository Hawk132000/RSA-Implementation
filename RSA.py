import random

'''partner's N & e are 775315049 & 72084229 '''


options = {
    1: 'Generate Keys',
    2: 'Encrypt',
    3: 'Decrypt',
    4: 'Sign',
    5: 'Verify',
    6: 'Exit',
}

def menu():
    for option in options.keys():
        print (option, ':', options[option] )

''' Function : To check prime '''
def isPrime(a):
    if a > 1:
        for i in range(2, int(a/2)+1):
            if (a % i) == 0:
                return False
        return True
    
    else:
        return False

''' Function : To get prime no's '''
def getPrimeNo():
    while True:
        z = random.randrange(32769, 65532)
        if isPrime(z):
            return z

''' Function : To calcuate gcd '''
def gcd(a,b):
	if(b==0):
		return a
	else:
		return gcd(b,a%b)

''' Function : To calculate Inverse of e :
	using Extended Eculidean Method '''
def inverse(a, b) : 
    b1 = b 
    y = 0
    x = 1
    if (b == 1) :
        return 0
    while (a > 1) : 
        q = a // b 
        t = b 
        b = a % b 
        a = t 
        t = y 
        y = x - q * y 
        x = t 
    # Make number positive by adding b1
    if (x < 0) : 
        x = x + b1 
  
    return x 

''' Key generator Function '''
def generate_keypair(p, q,f,n):
    #Choose an random integer from range 2  - f(n)
    e = random.randrange(2, f)
    # check (e , f(n)) are comprime
    g = gcd(e, f)
    while g != 1:
        e = random.randrange(2, f)
        g = gcd(e, f)

    #call to Extended Eculidean function
    d = inverse(e, f)
    
    #Keypairs
    return ((e, n), (d, n))


''' Function : To generate keys '''
def generate_keys():

    p = getPrimeNo()
    q = getPrimeNo()

    n = p*q     # n=pq       
                                            
    f = (p-1)*(q-1)  # f(n)=(p-1)(q-1)   
    primes = (p,q)
    publicKey , privateKey = generate_keypair(p,q,f,n)
    print("(p,q) : ", primes)
    print("FiN : ", f)
    print("(e,n) : ", publicKey)
    print("(d,n) : ", privateKey)

    return publicKey, privateKey



hex_list = []
num_list = []
cipher_list = []

''' Function : To encrypt plaintext '''
def encrypt():
    e = int(input('value of e: '))
    n = int(input('value of n: '))
    publicKey = (e, n)
    print('Handle option \'Option 2\'')
    
    message = input('Enter message m = ') # Message to be encrypted
    print('Public Key [e,n] = ',publicKey)

    # convert message into chunks of 3 each
    chunks = [message[i:i+3] for i in range(0, len(message), 3)]
    print(chunks)

    #perform actions on every chunk
    for i in chunks:
        #encode chunks to Hexadecimal
        hexa  = i.encode().hex()
        #convert Hexadecimal to Interger
        num = int(hexa, 16)
        hex_list.append(hexa)
        num_list.append(num)
        #encrypt using m^e mod n
        cipher = pow(num, e, n)
        cipher_list.append(cipher)
    #return Lists
    return hex_list, num_list, cipher_list

plain_list = []

''' Function : To decrypt cipher '''
def decrypt():
    ciphers = [296903278, 1581324012, 1457336654, 485798237, 1066240178, 561749684, 1264687844]
    
    # d = int(input('value of d: '))
    # n = int(input('value of n: '))
    # p = int(input('value of p: '))
    # q = int(input('value of q: '))
    d = 740376845
    p = 46523
    q = 36383
    n = 1692646309

    # p=56941
    # q=51461
    # n=2930240801
    # d=2813983841
    # ciphers = [1143665784, 2272409881, 1222390195, 2139764264]

    for i in ciphers:
        # By chinese Reminder Theorem
        mp = inverse(q,p)
        mq = inverse(p,q)
        dp = d % (p-1)
        dq = d % (q-1)
        xp = i**dp % p
        xq = i**dq % q
        x = ((mp*q*xp)+(mq*p*xq))%n
        # convert number to Hexadecimal
        hexa = hex(x)
        hexa = hexa.replace("0x","")
        byte_objects = bytes.fromhex(hexa)
        # Convert to ASCII
        plain = byte_objects.decode("ASCII")

        plain_list.append(plain)
    return plain_list

def square_and_multiply(i, d, n):
    r = 1
    for bit in list(bin(d)[2:]):
        r = (r * r) % n
        if int(bit) == 1:
            r = (r * i) % n
    return r

def signature_sign():
    d = 740376845
    n = 1692646309
    sign_hex_list = []
    sign_num_list = []
    sign_sign = []
    message = "Himanshu" # Message to be encrypted
    print(message)

    # convert message into chunks of 3 each
    chunks = [message[i:i+3] for i in range(0, len(message), 3)]
    print(chunks)
 
         
    #perform actions on every chunk
    for i in chunks:
        # encode chunks to Hexadecimal
        hexa  = i.encode().hex()
        #convert Hexadecimal to Interger
        num = int(hexa, 16)
        sign_hex_list.append(hexa)
        sign_num_list.append(num)
        sign = square_and_multiply(num, d, n)
        sign_sign.append(sign)

    return sign_sign




def signature_verify():
    e = 72084229
    n = 775315049

    plain_list = []
    message = "Himani Rajput" # Message to be encrypted
    signature = [649383299, 344090736, 465105025, 282068103, 228150614]
    print(message)
    print(signature)
         
    #perform actions on every chunk
    for i in signature:
        x = square_and_multiply(i, e, n)
        hexa = hex(x)
        hexa = hexa.replace("0x","")
        byte_objects = bytes.fromhex(hexa)
        # Convert to ASCII
        plain = byte_objects.decode("ASCII")
        plain_list.append(plain)

    print(plain_list)
    if message == "".join(plain_list):
        print('IS_VALID_SIGNATURE = True')
    else:
        print('IS_VALID_SIGNATURE = False')





''' Main '''
if __name__=='__main__':
    while(True):
        menu()
        option = ''
        try:
            option = int(input('Enter your choice: '))
        except:
            print('Wrong input. Please enter a number ...')
        #Check what choice was entered and act accordingly
        if option == 1:
           generate_keys()

        elif option == 2:
            encrypt()
            print(hex_list)
            print(num_list)
            print("Encrypted text : ",cipher_list)
            
        elif option == 3:
            decrypt()
            print(plain_list)
            print("Partner's Decrypted Message is : " + "".join(plain_list))

        elif option == 4:
           out = signature_sign()
           print(out)

        elif option == 5:
           signature_verify()

        elif option == 6:
            print('Thanks you for computing')
            exit()

        else:
            print('Invalid option. Please enter a number between 1 and 4.')