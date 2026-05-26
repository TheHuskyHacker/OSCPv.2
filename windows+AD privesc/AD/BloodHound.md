# Blood Hound Install 
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/a6d42f77-b4ef-41f3-a3bb-1c1a7879c201" />

## Steps
```
sudo apt update 
```
```
sudo apt install -y docker.io docker-compose
```
```
sudo usermod -aG docker kali
```
```
id kali | grep docker
```

```
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```
```
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
```
```
chmod +x bloodhound-cli
```
```
sudo ./bloodhound-cli install
```
Save your password: The install command will output a randomly generated password for the admin user. Copy this immediately, as you will need it to log in at http://localhost:8080.

Note: If you forget your password or issues with the password:
```
Bloodhound-cli resetpwd
```

Once done:
<img width="1893" height="72" alt="image" src="https://github.com/user-attachments/assets/1e18160d-6371-4214-9291-32d276cb9545" />

Copy the password and sign in web: http://127.0.0.1:8080/ui/login

<img width="1527" height="815" alt="image" src="https://github.com/user-attachments/assets/db37772e-5f21-4a0d-9745-78bdcdb9ce13" />

Now you can upload any content from Bloodhound. 

## Commands

### Sharhound:

```
.\SharpHound.exe -c All --zipfilename loot.zip
```
```
.\SharpHound.exe -c DCOnly
```
### Bloodhound python
```
bloodhound-python -u USER -p PASSWORD -d DOMAIN.local -dc dc01.domain.local -ns DC_IP -c All
```
### Netexec
```
nxc ldap dc01.domain.local -u user -p '' --bloodhound --collection All --dns-server $target
```

### Pass the Hash

```
nxc ldap dc01.domain.local -u administrator -H NTLMHASH --bloodhound --collection All
```
```
bloodhound-python -d <DOMAIN> -u <USERNAME> --hashes :<NTLM_HASH> -c All -ns <NAMESERVER_IP>
```
## Follow Kali as well:

https://www.kali.org/tools/bloodhound/
