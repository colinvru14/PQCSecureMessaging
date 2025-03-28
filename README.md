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
We have created two real-time messaging apps, the main one utilizes PQC algorithms to protect against quantum computer attacks, and the other uses traditional encryption algorithms (RSA). This more basic program is used as a benchmark so we can test our PQC app against technology that has been implemented in real-world applications.

To test the traditional cryptography messaging app:
1. Clone this repository
2. Open QNX Momentics
3. Build the project with the hammer icon in the top right (this should raise two warnings which you can ignore, but should also create two binary files)
4. Run the `receiver` binary file as a QNX Application
5. Run the `sender` binary file as a QNX Application. The receiver should say it connected to the sender
6. Switch to the sender console, and enter a message to send to the receiver. This will encrypt the message and send
7. Switch to the receiver console, and you can observe that it decrypted the message and you can see the original plaintext

[Video Explanation](https://drive.google.com/file/d/1uPVCcjNTHvR51fxKOBZVn2DErSPSGNBk/view?usp=drive_link)