from brownie import Hawk, PourVerifier, FreezeVerifier, ComputeVerifier, FinalizeVerifier, WithdrawVerifier
from scripts.utils import get_account
def deployVerifier():
    account = get_account()
    pourverifier = PourVerifier.deploy({"from": account})
    freezeVerifier = FreezeVerifier.deploy({"from": account})
    computeVerifier = ComputeVerifier.deploy({"from": account})
    finalizeVerifier = FinalizeVerifier.deploy({"from": account})
    
def deployHawk():
    account = get_account()
    hawk = Hawk.deploy(PourVerifier[-1], 
                       FreezeVerifier[-1], 
                       ComputeVerifier[-1], 
                       FinalizeVerifier[-1],
                       account,
                       [13831938532176550324958139758445033250885452427288105901790261247373594399825, # Manager.epk
                        1069949356836057373242838462873732805967900060420173004808443205495245038966,  # must be same as the Manager.epk in wallets.json
                        9332434120992362577266864387736774678434517414192378456190467378425163795557,
                        21413366313976831222063022121043159461836960586955963444923518988929911646504],
                       {"from": account})

def main():
    deployVerifier()
    deployHawk()