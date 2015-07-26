# Name: AES_cipher.py
# Purpose:  A simple python implementation of the Advanced Encryption Standard (AES)
#           Cipher.
# 
# Author Website: https://www.cybercitadellabs.com
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Brian S. Cain
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from copy import deepcopy
from galos import FFMulFast


# A Word in AES is 32 bits.
# Nb is Number of 32-bit words (number of columns) in the State

# A Helper Function to translate a Hex decimal value into a 2 byte string value
# Example: getHexString(255) = ff
getHexString = lambda hexVal: "{0:#0{1}x}".format(hexVal,4)[2:]

# A Helper Function to translate a an X, Y value into a value from a 
# 2-D Array.  This is used to translate the S-Box and State Values
getArrayVal = lambda x, y, source, columns: source[ y + x*columns ]


#  A helper function that sets the value in the given array.
def setArrayVal( x, y, source, columns, value ):
    source[ y + x * columns ] = value
   
# A Helper function that translates an integer to an Array value 
def toArr( val, fill=8 ):
    
    retVal = []
    newVal = hex(val)[2:].zfill(fill)
    it = iter(newVal)
    for x in it:
        retVal.append(int( x + next(it), 16))
    return retVal

# A Helper function that translates an Array value to an integer
toInt = lambda arrVal: int("".join('{:02x}'.format(x) for x in arrVal), 16)

def flattenKey( key ):
    """
    A Helper function that takes the nested array and transforms it into
    a flat array with no nesting.  E.g., [[a,b,c],[d,e,f]] transforms into
    [a,b,c,d,e,f]
    
    @param key:  The Key Schedule to flatten
    
    @return: The flattened key
    """ 
    retVal = []
    for i in key:
        for ii in i:
            retVal.append(ii)
    return retVal

################################################################################
###   Helper Varaiables that are used to select which version of the Algorithm
################################################################################
AES_128 = 4
AES_192 = 6
AES_256 = 8

class AES():
    _sboxColumns = 16
   
    _sbox = [ \
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 
      0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 
      0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 
      0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 
      0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 
      0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 
      0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 
      0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 
      0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 
      0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 
      0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 
      0xb0, 0x54, 0xbb, 0x16 ]
    
    _invsbox = [ \
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
      0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 
      0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 
      0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
      0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 
      0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 
      0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 
      0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 
      0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 
      0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 
      0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 
      0x55, 0x21, 0x0c, 0x7d]

    # Number of 32-bit words (number of columns) in the State
    _Nb = 4
   
    # _Nk is the Key Length 4, 6, 8
    _Nk = int()
   
    # Number of Rounds, 10, 12, 14
    _Nr = int() 
   
    # An Array of Integers that is less than or equal to 256
    _state = []
   
    def __init__(self, keyLength):
        """
        The Initializtion function for the AES Cipher Algorithm
        This determine the key length that will be utilized for 
        encryption and decryption
        
        @param keyLength:   A Key Length, AES_128, AES_192, AES_256
        """
        assert( keyLength == AES_128 or keyLength == AES_192 or keyLength == AES_256)
        self._Nk = keyLength
      
        if keyLength == AES_128:
            self._Nr = 10
        elif keyLength == AES_192:
            self._Nr = 12
        elif keyLength == AES_256:
            self._Nr = 14
        # end if
      
        # Calculate the RCON Table on the fly.  This could be statically coded
        # and achieve better performance, however I felt it would be better from 
        # an educational perspective to calculate it on the fly.
        self._rcon = self._CalculateRCON()
    # end __init__
   
    def _Cipher(self, inBlock, key):
        """
        The  Cipher operation.  This encrypts the given inBlock with
        the given key
        
        @param inBlock:  The block of bytes to encrypt
        @param key: The key that will be used to encrypt the inBlock
        
        @return: The encrypted block of bytes
        """
      
        keySchedule = self.KeyExpansion( key = key )
        
        # Assert that the initial state is likely valid, and assign it to the
        # current state variable
        assert( type(inBlock) == list )
        assert( len(inBlock) == 4 * self._Nb)
        for c in inBlock:
            assert( type(c) == int )
            assert( c < 256 )
        self._state = inBlock
        
        # Start of the Encryption    
        print( "rount[ 0].input : " + "".join([hex(x)[2:].zfill(2) for x in self._state]))   
        self.AddRoundKey( keySchedule[0: self._Nb] )
        for r in range(1, self._Nr):
            print( "rount[ %d].start : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.SubBytes()
            print( "rount[ %d].s_box : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.ShiftRows()
            print( "rount[ %d].s_row : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.MixColumns()
            print( "rount[ %d].s_col : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.AddRoundKey( keySchedule[r*self._Nb : (r+1)*self._Nb] )  
        # end for
        
        self.SubBytes()
        self.ShiftRows()
        self.AddRoundKey( keySchedule[self._Nr*self._Nb: (self._Nr+1)*self._Nb])
        return self._state
    # end _Cipher
    
    def _InvCipher(self, inBlock, key):
        """
        The Inverse Cipher operation.  This decrypts the given inBlock with
        the given key
        
        @param inBlock:  The block of bytes to decrypt
        @param key: The key that will be used to decrypt the inBlock
        
        @return: The decrypted block of bytes
        """
        keySchedule = self.KeyExpansion( key = key )
        
        # Assert that the initial state is likely valid, and assign it to the
        # current state variable
        assert( type(inBlock) == list )
        assert( len(inBlock) == 4 * self._Nb)
        for c in inBlock:
            assert( type(c) == int )
            assert( c < 256 )
        self._state = inBlock
        print( "rount[ 0].iinput : " + "".join([hex(x)[2:].zfill(2) for x in self._state]))
        self.AddRoundKey(keySchedule[self._Nr*self._Nb: (self._Nr+1)*self._Nb])
        print( "round[ 0].ik_sch : " + "".join([hex(x)[2:].zfill(2) for x in flattenKey(keySchedule[self._Nr*self._Nb: (self._Nr+1)*self._Nb])]))
        for r in reversed(range(1, self._Nr)):
            print( "rount[ %d].istart : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.ShiftRows(inverse = True)
            print( "rount[ %d].is_row : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.SubBytes(inverse = True)
            print( "rount[ %d].is_box : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
            self.AddRoundKey( keySchedule[r*self._Nb : (r+1)*self._Nb] )
            print( "round[ %d].ik_sch : " %r + "".join([hex(x)[2:].zfill(2) for x in flattenKey(keySchedule[r*self._Nb : (r+1)*self._Nb])]))
            self.MixColumns(inverse = True)
            print( "rount[ %d].ik_add : " %r + "".join([hex(x)[2:].zfill(2) for x in self._state]))
        # end for
        
        self.ShiftRows(inverse = True)
        self.SubBytes(inverse = True)
        self.AddRoundKey( keySchedule[0: self._Nb] )
        print( "rount[ ].ioutput : " + "".join([hex(x)[2:].zfill(2) for x in self._state]))
        return self._state
   
   
    def KeyExpansion(self, key):
        """
        The Key Expansion algorithm takes the Cipher Key and perform a key 
        expansion routine to generate a key schedule that is used for each
        round of encryption / decryption
        
        @param key: The key to produce the key schedule from
        
        @return: The Key schedule as a array of an array of bytes
        """
        
        tempKey = []
        # Convert the key from an array of bytes into an array of "words"
        # which in the AES specification is 32 bit words or 4 bytes
        for i in range(0, len(key), 4):
            tempKey.append(key[i:i+4])
        
        # Build a temporary array to hold the expanded key schedule
        w = [0] * (self._Nb * (self._Nr+1))
        
        i = 0
        while i < self._Nk:
            w[i] = tempKey[i]
            i += 1
        # end while
        
        while( i< self._Nb * (self._Nr + 1 )):
            temp = w[i-1]
           
            if( i % self._Nk == 0 ):
                temp = toArr(
                        toInt(
                          self.SubWord(self.RotWord(temp))) ^ self._rcon[int(i/self._Nk)])            
        
            elif( self._Nk > 6 and i % self._Nk == 4):
                temp = self.SubWord(temp)
            # end if
            w[i] = toArr( toInt(w[i-self._Nk]) ^ toInt(temp) )
            i += 1
        # end while
              
        return w
    # end KeyExpansion
   
    # [S'0,c, S'1,c, S'2,c, S'3,c] = [S0,c, S1,c, S2,c, S3,c] XOR (Wround+Nb+c)
    def AddRoundKey(self, roundKey):
        """
        In the AddRoundKey transformation, a Round Key is added to the State by 
        a simple bitwise XOR operation.  Each RoundKey consists of Nb words from 
        the key schedule.  
        
        @param roundKey:  The length 16 array of integers representing the Key
        
        @return: None, the state variable is modified directly.
        """
      
        # The roundKey is a list of lists at this point, flatten it to a standard
        # byte array
        key = []
        for i in roundKey:
            for ii in i:
                key.append(ii)
            # end for ii in in
        # end for i in roundKey
        
        for i in range( len(self._state)):
            self._state[i] ^= key[i]
        # end for i in range( len(self._state))
      
    # end AddRoundKey
       

    def SubBytes(self, inverse = False):
        """
        Subbyes transformation is a non-linear byte substitution that operates 
        independently on each byte of the State using the Substitution (S-box) 
        
        @param inverse:  If value is true the inverse operation is performed
        
        @return: None.  The State variable is directly modified. 
        """
        
        if inverse == True:
            sBox = self._invsbox
        else:
            sBox = self._sbox
        # end if    
        
        for x in range(self._Nb):
            for y in range(self._Nb):
                # Get the current State Value
                value = getArrayVal(x = x,
                                    y = y,
                                    source = self._state,
                                    columns = self._Nb)
                
                # Split the Hex values into two independent addresses in the 
                # SBox.  For example, if the value returned was 0x53, 
                # X = 5, Y = 3 and the SBox return would be 0xed.
                xVal = int(hex(value)[2:].zfill(2)[0], 16)
                yVal = int(hex(value)[2:].zfill(2)[1], 16)
                
                # Gather the SBox Value
                newVal = getArrayVal(x = xVal,
                                     y = yVal,
                                     source = sBox, 
                                     columns = self._sboxColumns)
                # Finally set the new value with the value that was gathered from 
                # S Box
                setArrayVal(x = x, 
                            y = y,
                            source =  self._state, 
                            columns = self._Nb, 
                            value = newVal)
               
            # end for y in range(self._Nb)
        # end for x in range(self._Nb)
              
    # end SubBytes
            
   
    def ShiftRows(self, inverse = False):
        """
        In the ShiftRows transformation, the bytes in the last three rows of the 
        state are cyclically shifted over different number of bytes (offsets)  
        The first row, r=0, is not shifted.
        
        @param inverse:  If value is true the inverse operation is performed
        
        @return: None.  The class state variable is directly modified.
        """
          
        # First make a copy of the state array so we can maintain the values
        # even after modifying the original state
        tempState = deepcopy(self._state)
        
        # Shift to the left or Right based on if this is an inverse operation
        if inverse == True:
            shiftVal = -1
        else:
            shiftVal = 1
        # end if
        # For the X value only iterate over the last 3 rows.  The first row
        # does not shift.
        for x in range(1, self._Nb):
            for y in range(self._Nb):
                # Update the value based on the shiftVal (which could be assigned 
                # to X but is shiftVal for added clarity)
                # The y column is shifted and the modular operator operator is 
                # applied to perform the actual circular shift 
                value = getArrayVal(x = (y+shiftVal) % self._Nb,
                                    y = x,
                                    source = tempState,
                                    columns = self._Nb)
                
                # Update the actual array value
                setArrayVal(x = y, 
                            y = x,
                            source =  self._state, 
                            columns = 4, 
                            value = value)
            # end for y in range(4)
            
            if inverse == True:
                shiftVal -= 1
            else:
                shiftVal += 1
            
        # end for x in range 1, 4
    # end ShiftRows   
   
    def MixColumns(self, inverse = False):
        """
        The MixColumns operation operates on the State column-by-column, treating 
        each column as a four-term polynomial.  The columns are considered as 
        polynomials over GF(2^8) and multiplied modulo x^4+1.
        
        @param inverse:  If value is true the inverse operation is performed
        
        @return: None, the state is modified directly
        """ 
        for y in range(self._Nb):
            column = [ \
               getArrayVal(y, 0, self._state, self._Nb),
               getArrayVal(y, 1, self._state, self._Nb),
               getArrayVal(y, 2, self._state, self._Nb),
               getArrayVal(y, 3, self._state, self._Nb) ]
            
            # Update the Column Field
            if inverse == True:
                column = self._InvMixColumn(column)
            else:
                column =  self._MixColumn(column)
            
            # Assign the values back into the State Array
            setArrayVal(y, 0, self._state, self._Nb, column[0])
            setArrayVal(y, 1, self._state, self._Nb, column[1])
            setArrayVal(y, 2, self._state, self._Nb, column[2])
            setArrayVal(y, 3, self._state, self._Nb, column[3])
        # end for y in range( self._Nb):
    # end MixColumns
   
    def SubWord(self, vals):
        """
        Subword is a function that takes a four-byte input word and applies the
        S-Box to each of the four bytes to produce an output word.  This is used 
        by the Key expansion algorithm.
        
        @param vals: The Byte Array of the values to Substitute
        
        @return: The Substituted values
        """ 
        retVal = []
        for val in vals:
            # Split the Hex values into two independent addresses in the 
            # SBox.  For example, if the value returned was 0x53, 
            # X = 5, Y = 3 and the SBox return would be 0xed.
            xVal = int(hex(val)[2:].zfill(2)[0], 16)
            yVal = int(hex(val)[2:].zfill(2)[1], 16)
            
            # Gather the SBox Value
            newVal = getArrayVal(x = xVal,
                                 y = yVal,
                                 source = self._sbox, 
                                 columns = self._sboxColumns)
            
            retVal.append(newVal)
        # end for v al in vals
        
        return retVal
    # end SubWord
   
    def RotWord(self, vals):
        """
        This function rotates the Word (4 Bytes) as follows:
        [a0, a1, a2, a3] into [a1, a2, a3, a0]
        
        @param vals:   The Values to rotate
        
        @return: The Rotated values as an array 
        """
        return vals[1:] + vals[0:1]
    # end RotWord
   
    #############################################################################
    # Helper Functions
    #############################################################################
    def _MixColumn(self, column):
        """
        This function mixes an individual column based on the AES Spec the 
        following formula gives the values
        s'0,c = ({02} . S0,c) ^ ({03} . S1,c) ^ S2,c          ^ S3,c
        s'1,c = S0,c          ^ ({02} . S1,c) ^ ({03} . S2,c) ^ S3,c
        s'2,c = S0,c          ^ S1,c          ^ ({02} . S2,c) ^ ({03} . S3,c)
        s'3,c = ({03} . S0,c) ^ S1,c          ^ S2,c          ^ ({02} . S3,c)
        
        @param column:  The Column values to update in a list.  
        
        @return: The list of updated column values 
        """
        t = deepcopy(column)
        column[0] = FFMulFast(2, t[0]) ^ FFMulFast(3, t[1]) ^ t[2] ^ t[3]
        column[1] = t[0] ^ FFMulFast(2, t[1]) ^ FFMulFast(3, t[2]) ^ t[3]
        column[2] = t[0] ^ t[1] ^ FFMulFast(2, t[2]) ^ FFMulFast(3, t[3])
        column[3] = FFMulFast(3, t[0]) ^ t[1] ^ t[2] ^ FFMulFast(2, t[3])
        
        return column
    # end _MixColumn
    
    def _InvMixColumn(self, column):
        """
        This function mixes an individual column based on the AES Spec the 
        following formula gives the values
        s'0,c = ({0e} . S0,c) ^ ({0b} . S1,c) ^ ({0d} . S2,c) ^ ({09} . S3,c)
        s'1,c = ({09} . S0,c) ^ ({0e} . S1,c) ^ ({0b} . S2,c) ^ ({0d} . S3,c)
        s'2,c = ({0d} . S0,c) ^ ({09} . S1,c) ^ ({0e} . S2,c) ^ ({0b} . S3,c)
        s'3,c = ({0b} . S0,c) ^ ({0d} . S1,c) ^ ({09} . S2,c) ^ ({0e} . S3,c)
        
        @param column:  The Column values to update in a list.  
        
        @return: The list of updated column values 
        """
        t = deepcopy(column)
        column[0] = FFMulFast(0x0e, t[0]) ^ FFMulFast(0x0b, t[1]) ^ FFMulFast(0x0d, t[2]) ^ FFMulFast(0x09, t[3])
        column[1] = FFMulFast(0x09, t[0]) ^ FFMulFast(0x0e, t[1]) ^ FFMulFast(0x0b, t[2]) ^ FFMulFast(0x0d, t[3])
        column[2] = FFMulFast(0x0d, t[0]) ^ FFMulFast(0x09, t[1]) ^ FFMulFast(0x0e, t[2]) ^ FFMulFast(0x0b, t[3])
        column[3] = FFMulFast(0x0b, t[0]) ^ FFMulFast(0x0d, t[1]) ^ FFMulFast(0x09, t[2]) ^ FFMulFast(0x0e, t[3])
        
        return column
    # end _MixColumn
   
    def _CalculateRCON(self):
        """
        This function calculates the RCON table used during the Key Expansion
        @return: None, the local rcon class value is updated directly
        """
        rcon = []
        
        # RCON of 0 is not used per the AES Specification.  RCON of 1 is 0x01 
        # which is 0x8D * 2 in a Galios Field of 2
        val = hex(int("0x8d", 16))
        rcon.append(int(val, 16))
        
        # The Variable I is not used in this equation, it is only used to create
        # a loop
        for i in range(256):
            val = hex(FFMulFast(int(val, 16),2 ))
            # TODO why 24
            rcon.append(int(val, 16) << 24)
        # end for i in range(256)
        return rcon
    # end _CalculateRCON
# end class AES