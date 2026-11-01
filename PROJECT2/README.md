# Encryption & Decryption (Caesar Cipher)
DecodeLabs · Cyber Security · Project 02

## Overview
A browser-based tool that encrypts and decrypts text with the Caesar cipher, a classical substitution cipher.
It uses only HTML, CSS and vanilla JavaScript: no server, database, libraries or installation.

## Objectives
- Accept user text and a shift key, encrypt it, show the ciphertext, then decrypt it back to the original.
- Demonstrate the idea of encryption and decryption and understand why the key matters.

## Features
Text input with character counter · shift key 1-25 with validation · Encrypt / Decrypt buttons ·
separate encrypted and decrypted output panels showing the shift used · copy buttons (Clipboard API with fallback) ·
"Insert example" button · Clear and Reset · "Try another shift" (changing the key re-encrypts automatically) ·
educational section and security notice · responsive, keyboard-accessible layout · no data stored or sent anywhere.

## Technologies
HTML5, CSS3 (variables, grid, media queries), JavaScript (ES6). `test.js` is optional and needs Node.js.

## The Caesar cipher
Each letter is replaced by the letter `shift` places later in the alphabet, wrapping from Z to A.
With shift 3: A→D, B→E, ... X→A, Y→B, Z→C. `HELLO WORLD` becomes `KHOOR ZRUOG`.
Digits, spaces, punctuation and line breaks are left unchanged, and upper/lower case is preserved.

## Encryption and decryption process
1. Read the text and the shift. Validate that the shift is a whole number from 1 to 25.
2. For each character, if it is a letter: convert it to 0-25 (`code - 65` for A-Z, `code - 97` for a-z),
   add the shift, take `% 26` to wrap around, and convert back. Otherwise keep it as is.
3. Decryption runs the same function with the **negative** shift. The formula `((shift % 26) + 26) % 26`
   makes negative shifts work correctly. Decrypt(Encrypt(text)) always equals the original text.

## Folder structure
```
caesar-cipher-project/
├── index.html    # page structure
├── style.css     # styling and responsive layout
├── script.js     # cipher logic + interface code
├── index-standalone.html  # same app in ONE file (backup if files get separated)
├── test.js       # optional logic tests (Node.js)
├── PRESENTATION.md
└── README.md
```

## Run on Windows
1. Extract the ZIP (right-click → Extract All).
2. Double-click `index.html` to open it in Chrome, Edge or Firefox. Nothing else is required.
3. Optional logic tests: install Node.js, open a terminal in the folder and run `node test.js`.

## Test cases
| Test | Input | Shift | Expected |
|---|---|---|---|
| 1 | HELLO WORLD | 3 | KHOOR ZRUOG |
| 2 | abc | 1 | bcd |
| 3 | XYZ | 3 | ABC |
| 4 | Hello, World! | 3 | Khoor, Zruog! |
| 5 | A | 25 | Z |
| 6 | (empty) | 3 | "Please enter some text to encrypt." |
| 7 | 123 !? | 5 | 123 !? |
| 8 | Hello World, xyz XYZ! | 7 | Olssv Dvysk, efg EFG! |

## Limitations
- Only 25 possible keys, so brute force breaks it instantly.
- Letter frequencies are preserved, so frequency analysis also breaks it.
- Only the 26 English letters are shifted; accented and non-Latin letters are left unchanged.
- It provides no integrity or authentication. It is for learning only, never for real secrets.

## Conclusion
This project shows the core concepts of encryption (plaintext, ciphertext, key, algorithm) and why modern systems
use much stronger algorithms such as AES.

## Troubleshooting: page looks unstyled
`index.html`, `style.css` and `script.js` must be in the **same folder**. Double-clicking `index.html` *inside a ZIP*
opens only that one file, so the CSS and JS are missing and the page looks like plain HTML.
1. Right-click the ZIP, choose **Extract All**, and open `index.html` from the extracted folder.
2. If the files do get separated, the page shows a yellow warning banner. `index-standalone.html` works on its own.
3. Check in the browser: press F12, open the Network tab, refresh, and confirm `style.css` and `script.js` show status 200.
