from os import access
from brownie import FundMe
from scripts.helpful_scripts import get_account

def fund():
    fund_me = FundMe[-1]
    account = get_account()
    entance_fee = fund_me.getEntranceFee()
    print(entance_fee)
    fund_me.fund({"from":account, "value":39572806171648987})

def withdraw():
    fund_me = FundMe[-1]
    account = get_account()
    fund_me.withdraw({"from":account})

def main():
    fund()
    withdraw()