from brownie import Hawk, PourVerifier, FreezeVerifier, ComputeVerifier, FinalizeVerifier, WithdrawVerifier
from scripts.utils import get_account
def deployVerifier():
    account = get_account()
    pourverifier = PourVerifier.deploy({"from": account})
    freezeVerifier = FreezeVerifier.deploy({"from": account})
    computeVerifier = ComputeVerifier.deploy({"from": account})
    finalizeVerifier = FinalizeVerifier.deploy({"from": account})
    withdrawVerifier = WithdrawVerifier.deploy({"from": account})
    
def deployHawk():
    account = get_account()
    hawk = Hawk.deploy(PourVerifier[-1], 
                       FreezeVerifier[-1], 
                       ComputeVerifier[-1], 
                       FinalizeVerifier[-1], 
                       WithdrawVerifier[-1],
                       account,
                       ["%064x" % 2983617551792014768146968712390766240725061529288144701201443216879521890304, 
                        "%064x" % 2678449094952908322156435173201880046459596063206772359138020062034866995200,
                        "%064x" % 7811834178409231860889403268620426021806520482792419800356457978805524365312,
                        "%064x" % 13594426744964245533667542599297066085398911875204889172438778928364884328448],
                       {"from": account})

def main():
    deployVerifier()
    deployHawk()