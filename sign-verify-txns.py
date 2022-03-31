#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import dataclasses
import time
from typing import Optional, cast

import algosdk
from algosdk import encoding
from algosdk.kmd import KMDClient
from algosdk.wallet import Wallet
from algosdk.v2client import algod
from algosdk.future import transaction
from algosdk.future.transaction import PaymentTxn
from algosdk.encoding import decode_address
from algosdk import mnemonic, util

from algosdk.atomic_transaction_composer import (
    TransactionSigner,
)
from nacl.encoding import Base32Encoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ALGOD_ADDRESS = "http://localhost:4001"
ALGOD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
KMD_ADDRESS = "http://localhost:4002"
KMD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
USING_SANDBOX = True

ASSET_UNIT_NAME = "USDC"
ASSET_NAME = "USDC"
ASSET_TOTAL = int(2**32)
ASSET_DECIMALS = 6
FUND_ACCOUNT_ALGOS = util.algos_to_microalgos(100)  # Algos
ASSET_DECIMALS_MULTIPLIER = int(10**ASSET_DECIMALS)

# 2 tenth of Algo, to exist on chain + asset opt-in
MIN_SC_BALANCE = util.algos_to_microalgos(0.1 * 2)
MIN_FLAT_FEE = util.algos_to_microalgos(0.001)  # 1 millialgo
MIN_FLAT_FEE_INNER = MIN_FLAT_FEE * 2
MAX_WAIT_ROUNDS = 10

algod_client = algod.AlgodClient(algod_token=ALGOD_TOKEN, algod_address=ALGOD_ADDRESS)

kmd_client = KMDClient(kmd_token=KMD_TOKEN, kmd_address=KMD_ADDRESS)


@dataclasses.dataclass(frozen=True)
class Account(TransactionSigner):
    address: str
    private_key: Optional[
        str
    ]  # Must be explicitly set to None when setting `lsig` or `app`.
    lsig: Optional[transaction.LogicSig] = None
    app: Optional[int] = None

    def __post_init__(self):
        assert self.private_key or self.lsig or self.app

    def mnemonic(self) -> str:
        return mnemonic.from_private_key(self.private_key)

    def is_lsig(self) -> bool:
        return bool(not self.private_key and self.lsig)

    @classmethod
    def create_account(cls) -> "Account":
        private_key, address = algosdk.account.generate_account()
        return cls(private_key=private_key, address=cast(str, address))

    @property
    def decoded_address(self):
        return encoding.decode_address(self.address)

    def sign_transactions(
        self, txn_group: list[transaction.Transaction], indexes: list[int]
    ) -> list:
        # Enables using `self` with `AtomicTransactionComposer`
        stxns = []
        for i in indexes:
            stxn = sign(self, txn_group[i])  # type: ignore
            stxns.append(stxn)
        return stxns


def get_params(client: algod.AlgodClient, fee=None) -> transaction.SuggestedParams:
    params = client.suggested_params()
    params.flat_fee = True
    params.fee = fee or MIN_FLAT_FEE

    return params


def create_pay_txn(sender: Account, receiver: Account, amount: int, note: str) -> PaymentTxn:
    sp = get_params(algod_client)
    return PaymentTxn(sender.address, sp, receiver.address, amount, None, note.encode())


def sign(account: Account, txn):
    if account.is_lsig():
        return transaction.LogicSigTransaction(txn, account.lsig)  # type: ignore
    else:
        assert account.private_key
        return txn.sign(account.private_key)


def sign_send_wait(account, txn):
    """Sign a transaction, submit it, and wait for its confirmation."""
    signed_txn = sign(account, txn)
    tx_id = signed_txn.transaction.get_txid()
    transaction.write_to_file([signed_txn], "/tmp/txn.signed", overwrite=True)
    algod_client.send_transactions([signed_txn])
    transaction.wait_for_confirmation(algod_client, tx_id)

    return algod_client.pending_transaction_info(tx_id)


def create_asset(creator_account: Account, total: int = ASSET_TOTAL) -> int:
    """Create an asset and return its ID."""
    params = get_params(algod_client)

    txn = transaction.AssetConfigTxn(
        sender=creator_account.address,
        sp=params,
        total=total,
        default_frozen=False,
        unit_name=ASSET_UNIT_NAME,
        asset_name=ASSET_NAME,
        manager=creator_account.address,
        reserve=creator_account.address,
        freeze=creator_account.address,
        clawback=creator_account.address,
        decimals=ASSET_DECIMALS,
    )

    ptx = sign_send_wait(creator_account, txn)
    return ptx["asset-index"]


def optin_to_asset(account: Account, asset_id: int):
    params = get_params(algod_client)
    txn = transaction.AssetTransferTxn(
        sender=account.address,
        sp=params,
        receiver=account.address,
        amt=0,
        index=asset_id,
    )
    return sign_send_wait(account, txn)


def transfer_asset(sender: Account, receiver: Account, asset_id: int, amount: int):
    params = get_params(algod_client)
    txn = transaction.AssetTransferTxn(
        sender=sender.address,
        sp=params,
        receiver=receiver.address,
        amt=amount,
        index=asset_id,
    )
    return sign_send_wait(sender, txn)


def compile_program(source_code: str) -> bytes:
    compile_response = algod_client.compile(source_code)
    return base64.b64decode(compile_response["result"])


def find_sandbox_faucet() -> Account:
    default_wallet_name = kmd_client.list_wallets()[0]["name"]
    wallet = Wallet(
        default_wallet_name, "", kmd_client
    )  # Sandbox's wallet has no password

    for account_ in wallet.list_keys():
        info = algod_client.account_info(account_)
        if (
            info
            and info.get("status") == "Online"
            # and info.get("created-at-round", 0) == 0  # Needs the indexer.
        ):
            return Account(address=account_, private_key=wallet.export_key(account_))

    raise KeyError("Could not find sandbox faucet")


def create_and_fund(faucet: Account) -> Account:
    new_account = Account.create_account()
    print(f"Funding new account: {new_account.address}.")

    fund(faucet, new_account)

    return new_account


def fund(faucet: Account, receiver: Account, amount=FUND_ACCOUNT_ALGOS):
    params = get_params(algod_client)
    txn = transaction.PaymentTxn(faucet.address, params, receiver.address, amount)
    return sign_send_wait(faucet, txn)


def get_last_round():
    return algod_client.status()["last-round"]


def wait_until_round(r):
    print(f" --- ⏲️  Waiting until round: {r}.")
    if USING_SANDBOX and r - get_last_round() > 0:
        generate_blocks(r - get_last_round(), find_sandbox_faucet())
    while get_last_round() < r:
        time.sleep(1)


def generate_blocks(num_blocks: int, account: Account):
    for _ in range(num_blocks):
        txn = transaction.PaymentTxn(
            sender=account.address,
            sp=algod_client.suggested_params(),
            receiver=account.address,
            amt=0,
        )
        sign_send_wait(account, txn)


def get_account_balance(account: Account) -> dict[int, int]:
    account_info = algod_client.account_info(account.address)
    balances = {a["asset-id"]: int(a["amount"]) for a in account_info["assets"]}
    balances[0] = int(account_info["amount"])
    return balances


def get_account_asa_balance(account: Account, asa_idx: int) -> int:
    return get_account_balance(account).get(asa_idx, 0)


def app_idx_to_account(app_idx: int) -> Account:
    return Account(
        cast(
            str,
            encoding.encode_address(
                encoding.checksum(b"appID" + app_idx.to_bytes(8, "big"))
            ),
        ),
        private_key=None,
        app=app_idx,
    )


def get_pub_key(account: Account):
    decode_addr = decode_address(account.address)
    print(decode_addr)
    return decode_addr


def verify_transaction(public_key, txn, signature):
    """
        Verify the signature of a transaction that was prepended with "TX" for domain
        separation.
        Args:
            message (bytes): message that was signed, without prefix
            signature (str): base64 signature
            public_key (str): base32 address
        Returns:
            bool: whether or not the signature is valid
        """
    domain_sep = b"TX"
    encoded_txn = base64.b64decode(encoding.msgpack_encode(txn))
    message = domain_sep + encoded_txn

    decoded_sign = base64.b64decode(signature)

    verify_key = VerifyKey(public_key)

    try:
        verify_key.verify(message, decoded_sign)
        return True
    except BadSignatureError:
        return False


def deploy():
    faucet = find_sandbox_faucet()
    print(f" --- ⛲ Sandbox faucet account: {faucet.address}.")

    backend = create_and_fund(faucet)
    print(f" --- 🤖 Creating backend account: {backend.address}.")

    attacker = create_and_fund(faucet)
    print(f" --- 🤖 Creating attacker account: {attacker.address}.")

    backend_pub_key = get_pub_key(backend)
    print(f" --- 🤖 backend account pub key: {backend_pub_key}.")

    unsigned_txn = create_pay_txn(backend, backend, 0, "challenge123")
    signed_txn_obj = sign(backend, unsigned_txn)
    signed_txn = signed_txn_obj.transaction
    signature = signed_txn_obj.signature

    verified = verify_transaction(backend_pub_key, signed_txn, signature)

    if verified:
        print("Urra!")
    else:
        print("No :(")

    print(" --- 🎉 SignTxn demo ended successfully!")


if __name__ == "__main__":
    deploy()
