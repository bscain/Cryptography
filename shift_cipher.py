# Name: shift_cipher.py
# Purpose:  A simple python implementation of the Shift Cipher.
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
#f urnished to do so, subject to the following conditions:
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


from random import seed, randint
from re import sub

class shift:
   """
   Shift Cipher Class used to encrypt and decrypt messages using the
   Shift Cipher.
   
   Useage: From within a Python console issue the following commands.
   >>> import shift_cipher
   >>> cipher = shift_cipher.Shift()
   >>> cipherText = cipher.encrypt_message("Secret Message to be encrypted!")
   >>> plainText = cipher.decrypt_message(cipherText)
   """
   
   
   # Helper Variable used when translating from the ASCII representation to
   # our standard character representation.  (A->0; B->1 ... Z->25)
   __char_offset = ord('A')
   
   # The Key to use during encryption / decryption 
   __key = int()
   
   def __init__(self, key=None):
      """
      Name: __init__
      Purpose:  Python class initialization function.  This will establish the 
                secret key is none is given.
      
      Inputs:
         key:  Optional parameter to specify the key to use for the 
               encryption / decryption operation.  If No key is given one will 
               be automatically generated.
      
      Return: None
      """
      
      if key == None:
         self.generate_key( )
      else:
         self.set_key( key )
      # end if key == None 
   
   # end __init__
   
   def set_key(self, key):
      """
      Name: set_key
      Purpose: Set the Key to use during encryption / decryption
      
      Inputs: 
         key: An integer list with values ranging from 0 to 25
      
      Return: None
      """
      
      assert( type(key) == int )
      assert (key >= 0 and key <= 25)
      
      self.__key = key
         
   # end set_key
   
   
   def generate_key( self ):
      """
      Name:  generate_key
      Purpose: Generates key material that will be used when encrypting / 
               decrypting messages
      
      Return: None
      """
      self.__key = int()
      
      # Set the Random Number Seed to the current system time
      seed()
      
      # Generate the Key using the python random integer generator
      self.__key = randint(0,26)

   # end generate_key
   
   def get_key(self):
      """
      Name: get_key
      Purpose: Returns the key used for encryption / decryption
      
      Inputs: None
      
      Returns: The Key used for encryption / decryption
      """
      return self.__key
   # end get_key
   
   def encrypt_message( self, message ):
      """
      Name: encrypt_message
      Purpose: Encrypt the message with the stored key
      
      Inputs:
         message: The string representation of the message to encrypt
         
      Return: The message cipher text string
      """
      
      # Convert the message text into a plain text with all spaces and 
      # punctuation removed. 
      plainText = sub(r'[^A-Z]', '', message.upper())
      cipherText = ""
      
      charIndex = 0
      
      # Encrypt the message 1 character at a time
      while charIndex < len(plainText):
         cipherText += \
            self.__encrypt_character( plainText[charIndex], self.__key)
         charIndex += 1
      return cipherText
   # end encrypt_message
   
   def decrypt_message( self, cipherText ):
      """
      Name: decrypt_message
      Purpose: Encrypt the message with the stored key
      
      Inputs:
         cipherText: The cipher text of the message to decrypt
         
      Return: The message plain text string
      """
      
      plainText = ""
      
      charIndex = 0
      
      # Decrypt the message one character at a time.
      while charIndex < len(cipherText):
         plainText += \
            self.__decrypt_character( cipherText[charIndex], 
                               self.__key)
         charIndex += 1
      # end while charIndex < len(cipherText)
      
      return plainText
   
   def __encrypt_character( self, char, keyVal ):
      """
      Name: __encrypt_character
      Purpose: Encrypt a single character the given key value
      
      Inputs:
         char: The character to encrypt
         keyVal: The key value to encrypt the character with
         
      Return: The encrypted character
      """
      
      assert( type(char) == str )
      assert( len(char) == 1 )
      
      # Update the character to be our standard Alphabet mapping
      # A -> 0; B->1 ... Z -> 25
      x = ord(char) - self.__char_offset
      
      # Perform the Encryption
      retVal = ( x + keyVal ) % 26
      
      # Translate back to the standard ASCII mapping of the character
      # for display in python and translate it back into a string
      retVal = chr(retVal + self.__char_offset)
      
      return retVal
   # end encrypt_character
   
   def __decrypt_character( self, char, keyVal ):
      """
      Name: __decrypt_character
      Purpose: Decrypt a single character the given key value
      
      Inputs:
         char: The character to decrypt
         keyVal: The key value to decrypt the character with
         
      Return: The encrypted character
      """
      assert( type(char) == str )
      assert( len(char) == 1 )
      
      # Update the character to be our standard Alphabet mapping
      # A -> 0; B->1 ... Z -> 25
      x = ord(char) - self.__char_offset
      
      retVal = ( x - keyVal ) % 26
      
      # Translate back to the standard ASCII mapping of the character
      # for display in python and translate it back into a string
      retVal = chr(retVal + self.__char_offset)
      
      return retVal
   # end encrypt_character
# end class shift
