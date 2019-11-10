## NuCypher KMS
Key management utility for NuCypher (optional IPFS support)

## Getting Started

1) Clone Repo

    ```
    git clone https://github.com/viraja1/nucypher_kms.git
    ```
    
2) Change directory
    
   ```
   cd nucypher_kms
   ```
   
3) Install requirements (tested only for python 3.7)
    
   ```
   pip install -r requirements.txt
   ```
   
4) Run nucypher ursula in a new tab of terminal
   
   ```
   nucypher ursula run --dev --federated-only 
   ```
   
5) Run below examples in ipython console
   ```
   ipython 
   ``` 

## Examples

```
from nucypher_kms import KMS

# Share secret with yourself (Without IPFS)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr")
label, data_source_public_key, data = user1.encrypt_data(plaintext="sample plaintext")
print("encrypted data: {}".format(data))
pubkeys = user1.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
result = user1.decrypt_data(data_source_public_key=data_source_public_key, data=data, policy_info=policy_info)
print("decrypted data: {}".format(result))


# Share secret with another user (Without IPFS)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr")
user2 = KMS(ursula_url="localhost:10151", dir_name="user2", passphrase="6Yd5M-d=rZ4Ny?Nx")
label, data_source_public_key, data = user1.encrypt_data(plaintext="sample plaintext")
print("encrypted data: {}".format(data))
pubkeys = user2.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
result = user2.decrypt_data(data_source_public_key=data_source_public_key, data=data, policy_info=policy_info)
print("decrypted data: {}".format(result))


# Share secret with another user (With IPFS)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr")
user2 = KMS(ursula_url="localhost:10151", dir_name="user2", passphrase="6Yd5M-d=rZ4Ny?Nx")
label, data_source_public_key, ipfs_hash = user1.upload_data_ipfs(plaintext="sample plaintext")
print("IPFS hash: {}".format(ipfs_hash))
pubkeys = user2.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
shareable_code = user1.get_shareable_code(ipfs_hash=ipfs_hash, data_source_public_key=data_source_public_key,
                                          policy_info=policy_info)
print("Shareable code for user2: {}".format(shareable_code))
result = user2.fetch_data_ipfs(shareable_code=shareable_code)
print("decrypted data: {}".format(result))
```