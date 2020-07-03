from nucypher_kms import KMS
import os

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
# Start ipfs daemon locally before running the code (https://docs.ipfs.io/how-to/command-line-quick-start/#install-ipfs)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr",
            ipfs_addr="/ip4/127.0.0.1/tcp/5001/http")
user2 = KMS(ursula_url="localhost:10151", dir_name="user2", passphrase="6Yd5M-d=rZ4Ny?Nx",
            ipfs_addr="/ip4/127.0.0.1/tcp/5001/http")
label, data_source_public_key, hash_key = user1.upload_data(plaintext="sample plaintext", storage="ipfs")
print("encrypted data: {}".format(data))
print("hash key: {}".format(hash_key))
pubkeys = user2.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
shareable_code = user1.get_shareable_code(hash_key=hash_key, data_source_public_key=data_source_public_key,
                                          policy_info=policy_info, storage="ipfs")
print("Shareable code for user2: {}".format(shareable_code))
result = user2.fetch_data(shareable_code=shareable_code, storage="ipfs")
print("decrypted data: {}".format(result))


# Share secret with another user (With Sia Skynet)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr")
user2 = KMS(ursula_url="localhost:10151", dir_name="user2", passphrase="6Yd5M-d=rZ4Ny?Nx")
label, data_source_public_key, hash_key = user1.upload_data(plaintext="sample plaintext", storage="skynet")
print("encrypted data: {}".format(data))
print("hash key: {}".format(hash_key))
pubkeys = user2.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
shareable_code = user1.get_shareable_code(hash_key=hash_key, data_source_public_key=data_source_public_key,
                                          policy_info=policy_info, storage="skynet")
print("Shareable code for user2: {}".format(shareable_code))
result = user2.fetch_data(shareable_code=shareable_code, storage="skynet")
print("decrypted data: {}".format(result))


# Share secret with another user (With Arweave)
# Generate arweave wallet keyfile and store it in locally. It should have sufficient balance (https://www.arweave.org/wallet)
user1 = KMS(ursula_url="localhost:10151", dir_name="user1", passphrase="&W=nqr2N:,[2}sAr",
            arweave_wallet_file_path=os.path.expanduser("~/arweave.json"))
user2 = KMS(ursula_url="localhost:10151", dir_name="user2", passphrase="6Yd5M-d=rZ4Ny?Nx",
            arweave_wallet_file_path=os.path.expanduser("~/arweave.json"))
label, data_source_public_key, hash_key = user1.upload_data(plaintext="sample plaintext", storage="arweave")
print("encrypted data: {}".format(data))
print("hash key: {}".format(hash_key))
pubkeys = user2.pubkeys
policy_info = user1.share_data_access(pubkeys=pubkeys, label=label)
shareable_code = user1.get_shareable_code(hash_key=hash_key, data_source_public_key=data_source_public_key,
                                          policy_info=policy_info, storage="arweave")
print("Shareable code for user2: {}".format(shareable_code))
result = user2.fetch_data(shareable_code=shareable_code, storage="arweave")
print("decrypted data: {}".format(result))
