from brownie import Cash, Verifier, MockV3Aggregator, network, config
from scripts.helpful_scripts import (
    deploy_mocks, 
    get_account, 
    LOCAL_BLOCKCHAIN_ENVIRONMENTS
)
def deploy():
    account = get_account()
    verifier = Verifier.deploy({"from": account})
    cash = Cash.deploy(verifier, {"from": account})

def main():
    deploy()