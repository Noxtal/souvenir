# souvenir
<p align="center">
  <img src="static/icon.png" alt="icon" width=100/>
</p>
An open-source, straightforward but secure password manager with a built-in web server/interface.

> NOTE I am not in any way a certified, professional security expert, please use this software at your own risk. This project was meant for my personal use based on my own understanding of cybersecurity and cryptography I obtained with experience. I can not and will not guarantee full security, thus I am not responsible for any kind of intimate issue caused by this software. Still report any issue found, I will do my best to fix it as soon as possible.

## Features
- Built-in web server
- Entirely local (no internet connection required)
- Clean user-friendly interface
- No choice but dark theme
- AES-256 encryption (with pkcs7 padding)
- `bcrypt` hashing time optimization to limit brute-force attacks
- Secure session tokens using `crypto/rand`
- Efficient API routing using `gorilla/mux`

## Usage
1. Get the latest release from the [releases page](https://github.com/Noxtal/souvenir/releases).
2. Extract the corresponding archive in a folder of your choice.
3. Run souvenir.exe (Windows) or souvenir (Linux).
4. A web server will start on port 4444, your browser should open automatically.
5. Register your masterkey if you have not already done so. **You will only be able to see it once**.
6. You can now add and edit passwords to your vault.

## Screenshots
![Login Page](screenshots/login.png)
![Vault Page](screenshots/index.png)
![Service Page](screenshots/service.png)

## Etymology
**souvenir** (n.)
> 1775, "a remembrance or memory," from French souvenir (12c.), from Old French noun use of souvenir (v.) "to remember, come to mind," from Latin subvenire "come to mind," from sub "up from below" (see sub-) + venire "to come," from a suffixed form of PIE root *gwa- "to go, come." Meaning "token of remembrance, memento" is first recorded 1782.

## TODO
- [ ] Changing masterkey
- [ ] Deleting entries
- [ ] Link to the service's website
- [ ] Way to reset all data
- [ ] Handling HTTP status errors for the user