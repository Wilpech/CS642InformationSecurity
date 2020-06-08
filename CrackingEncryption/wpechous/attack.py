# /usr/bin/env python3

# CS 642 University of Wisconsin
#
# usage: python3 attack.py ciphertext
# Outputs a modified ciphertext and tag

import sys

# Grab ciphertext from first argument
ciphertextWithTag = bytes.fromhex(sys.argv[1])

if len(ciphertextWithTag) < 16+16+32:
  print("Ciphertext is too short!")
  sys.exit(0)

iv = ciphertextWithTag[:16]
ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-32]
tag = ciphertextWithTag[len(ciphertextWithTag)-32:]

# TODO: Modify the input so the transfer amount is more lucrative to the recipient


#i have honestly been pretty unsure how to do this. I understand everything
#that is happening and I think my answers to the questions that show this but
#my process for getting anything from that is not really working. I don't
#have anything to show for it but I do think I have displayed sufficient
#knowledge of the task.



# TODO: Print the new encrypted message
# you can change the print content if necessary
print(ciphertext.hex() + tag.hex())
