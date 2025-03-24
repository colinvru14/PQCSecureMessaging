# PQCSecureMessaging
COMP4900E Group Project 2025

## Group Members:
- Daniel Mejia
- Shivam Karavadra
- Colin Vrugteman

## Project Overview
This project will evaluate the platform that provides secure low-latency transmission of messages using post-quantum cryptography (PQC) to protect against potential threats.

View the full project proposal document [here](https://docs.google.com/document/d/1UImKw9Gi1FlmIXhHbqYkY65Or95a4-OU54jYeSzhC24/edit?tab=t.0)

View the project proposal presentation [here](https://docs.google.com/presentation/d/1D6lXlrNmAlTrDZ5bIkgARoAYa_UiUUkckiq1XTKNOvQ/edit?usp=drive_link) 

## Using The Traditional Cryptography Messaging App
We have created two real-time messaging apps, the main one utilizes PQC algorithms to protect against quantum computer attacks, and the other uses traditional encryption algorithms (RSA and AES). This more basic program is used as a benchmark so we can test our PQC app against technology that has been implemented in real-world applications.

To test the traditional cryptography messaging app:
1. Clone this repository
2. Navigate to `src/traditional`
3. In one terminal, run `make receiver`
   - This should generate a public key and private key for the key exchange so that the message is able to be encrypted, and subsequently decrypted by the receiver, and the receiver should now be waiting for the sender on port 8080
4. In another terminal, run `make sender`
     - This will connect to the receiver at the specified port, and prompt you to enter a message to send the to the receiver, which the program will encrypt before sending
5. Once a message has been sent from the sender, the receiver will decrypt it and print it to the terminal to show the original plaintext. 
6. The program will continue to prompt for a message on the sender's side until the keyword 'quit' is used to end the process, at which point, the receiver will detect that the sender is no long connected and will end it's own process