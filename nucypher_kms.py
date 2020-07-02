import os
import datetime
import json

import maya
import ipfshttpclient
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from nucypher.characters.lawful import Bob, Ursula, Enrico
from nucypher.utilities.logging import GlobalLoggerSettings
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.network.middleware import RestMiddleware
from nucypher.datastore.keypairs import DecryptingKeypair, SigningKeypair
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.config.characters import AliceConfiguration


GlobalLoggerSettings.start_console_logging()


def generate_keys(path):
    """
    Generate public and private keys

    Args:
         path (str): path where the public and private key files should be stored

    Returns:
        privkeys, pubkeys (dict, dict): private and public keys dict containing enc and sig keys
    """
    enc_privkey = UmbralPrivateKey.gen_key()
    sig_privkey = UmbralPrivateKey.gen_key()

    privkeys = {
        'enc': enc_privkey.to_bytes().hex(),
        'sig': sig_privkey.to_bytes().hex(),
    }
    with open(os.path.join(path, 'private.json'), 'w') as f:
        json.dump(privkeys, f)
    enc_pubkey = enc_privkey.get_pubkey()
    sig_pubkey = sig_privkey.get_pubkey()
    pubkeys = {
        'enc': enc_pubkey.to_bytes().hex(),
        'sig': sig_pubkey.to_bytes().hex()
    }
    with open(os.path.join(path, 'public.json'), 'w') as f:
        json.dump(pubkeys, f)
    return privkeys, pubkeys


def _get_keys(stored_keys, key_class):
    """
    Get keys

    Args:
         stored_keys (dict): key dict
         key_class (UmbralPrivateKey or mbralPublicKey): Used to generate key object from bytes

    Returns:
        keys (dict): dict containing enc and sig keys
    """
    keys = dict()
    for key_type, key_str in stored_keys.items():
        keys[key_type] = key_class.from_bytes(bytes.fromhex(key_str))
    return keys


def fetch_keys(path):
    """
    Fetch public and private keys (generate if does not exist)

    Args:
        path (str): path where the public and private key files exists or should be stored

    Returns:
        privkeys, pubkeys (dict, dict): private and public keys dict containing enc and sig keys
    """
    if not os.path.exists(os.path.join(path, 'private.json')) \
            or not os.path.exists(os.path.join(path, 'public.json')):
        privkeys, pubkeys = generate_keys(path=path)
    else:
        with open(os.path.join(path, "private.json")) as f:
            privkeys = json.load(f)
        with open(os.path.join(path, "public.json")) as f:
            pubkeys = json.load(f)
    return _get_keys(stored_keys=privkeys, key_class=UmbralPrivateKey), \
        _get_keys(stored_keys=pubkeys, key_class=UmbralPublicKey)


class KMS:
    def __init__(self, ursula_url, dir_name, passphrase):
        """
        Args:
            ursula_url (str): ursula url e.g. localhost:10151
            dir_name (str): dir_name where account files will be stored in tmp directory
            passphrase (str): passphrase for account
        """
        self.ursula_url = ursula_url
        self.ursula = Ursula.from_seed_and_stake_info(seed_uri=self.ursula_url,
                                                      federated_only=True,
                                                      minimum_stake=0)
        self.ipfs = ipfshttpclient.connect("/dns/ipfs.infura.io/tcp/5001/https")
        self.temp_dir = os.path.join('/', 'tmp', dir_name)
        self.alice_config = AliceConfiguration(
            config_root=os.path.join(self.temp_dir),
            domains={TEMPORARY_DOMAIN},
            known_nodes={self.ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )
        self.alice_config.initialize(password=passphrase)
        self.alice_config.keyring.unlock(password=passphrase)
        self.alice = self.alice_config.produce()
        self.alice_config_file = self.alice_config.to_configuration_file()
        self.alice.start_learning_loop(now=True)
        self.privkeys, self.pubkeys = fetch_keys(path=self.temp_dir)
        bob_enc_keypair = DecryptingKeypair(private_key=self.privkeys["enc"])
        bob_sig_keypair = SigningKeypair(private_key=self.privkeys["sig"])
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]
        self.bob = Bob(
            domains={TEMPORARY_DOMAIN},
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[self.ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )

    def encrypt_data(self, plaintext):
        """
        Encrypt data

        Args:
            plaintext (str): plaintext that should be encrypted

        Returns:
            label, data_source_public_key, data (bytes, bytes, byes): tuple containing label for the policy,
                                                                      data source public_key & encrypted data
        """
        label = ("policy️-" + os.urandom(8).hex()).encode()
        policy_pubkey = self.alice.get_policy_encrypting_key_from_label(label)
        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)
        message, _signature = data_source.encrypt_message(plaintext.encode("utf-8"))
        data = message.to_bytes()
        return label, data_source_public_key, data

    def decrypt_data(self, data_source_public_key, data, policy_info):
        """
        Decrypt data

        Args:
            data_source_public_key (bytes): data_source_public_key
            data (bytes): encrypted data
            policy_info (dict): dict containing policy_pubkey, alice_sig_pubkey and label keys

        Returns:
            retrieved_plaintexts (list): list of str
        """
        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_info["policy_pubkey"]))
        alice_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_info["alice_sig_pubkey"]))
        label = policy_info["label"].encode()
        self.bob.join_policy(label, alice_sig_pubkey)
        message_kit = UmbralMessageKit.from_bytes(data)
        data_source = Enrico.from_public_keys(
            verifying_key=data_source_public_key,
            policy_encrypting_key=policy_pubkey
        )
        retrieved_plaintexts = self.bob.retrieve(
            message_kit,
            label=label,
            enrico=data_source,
            alice_verifying_key=alice_sig_pubkey
        )
        retrieved_plaintexts = [x.decode('utf-8') for x in retrieved_plaintexts]
        return retrieved_plaintexts

    def share_data_access(self, pubkeys, label, days=5, m=1, n=1):
        """
        Share data access based on public keys

        Args:
            pubkeys (dict): public keys dict containing sig and enc keys
            label (bytes): label for the policy
            days (int): days for which the access should be granted
            m (int)
            n (int)

        Returns:
            policy_info (dict): dict containing policy_pubkey, alice_sig_pubkey and label keys
        """
        bob = Bob.from_public_keys(
            verifying_key=pubkeys['sig'],
            encrypting_key=pubkeys['enc'],
            federated_only=True
        )
        # Policy expiration date
        policy_end_datetime = maya.now() + datetime.timedelta(days=days)
        policy = self.alice.grant(
            bob=bob,
            label=label,
            m=m,
            n=n,
            expiration=policy_end_datetime
        )
        policy_info = {
            "policy_pubkey": policy.public_key.to_bytes().hex(),
            "alice_sig_pubkey": bytes(self.alice.stamp).hex(),
            "label": label.decode("utf-8"),
        }
        return policy_info

    def upload_data_ipfs(self, plaintext):
        """
        Upload data to ipfs

        Args:
            plaintext (str): plaintext

        Returns:
           label, data_source_public_key, ipfs_hash (bytes, bytes, str): tuple containing policy label,
                                                                         data source public key and ipfs hash
        """
        label, data_source_public_key, data = self.encrypt_data(plaintext=plaintext)
        ipfs_hash = self.ipfs.add_bytes(data)
        return label, data_source_public_key, ipfs_hash

    @staticmethod
    def get_shareable_code(ipfs_hash, data_source_public_key, policy_info):
        """
        Get shareable code to fetch the secret which can be shared easily

        Args:
             ipfs_hash (str): ipfs hash
             data_source_public_key (bytes): data source public key
             policy_info (dict): dict containing policy_pubkey, alice_sig_pubkey and label keys

        Returns:
             shareable_code (str): shareable code
        """
        return ipfs_hash + "_" + data_source_public_key.hex() + "_" + policy_info["policy_pubkey"] + "_" \
            + policy_info["alice_sig_pubkey"] + "_" + policy_info["label"]

    def fetch_data_ipfs(self, shareable_code):
        """
        Fetch data from ipfs and decrypt it

        Args:
            shareable_code (str): shareable code

        Returns:
            retrieved_plaintexts (list): list of str
        """
        ipfs_hash, data_source_public_key, policy_pubkey, alice_sig_pubkey, label = shareable_code.split("_")
        data = self.ipfs.cat(ipfs_hash)
        data_source_public_key = bytes.fromhex(data_source_public_key)
        policy_info = {
            "policy_pubkey": policy_pubkey,
            "alice_sig_pubkey": alice_sig_pubkey,
            "label": label,
        }
        return self.decrypt_data(data_source_public_key=data_source_public_key, data=data, policy_info=policy_info)
