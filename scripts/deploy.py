from brownie import Cash, FundMe, Verifier, MockV3Aggregator, network, config
from scripts.helpful_scripts import (
    deploy_mocks, 
    get_account, 
    LOCAL_BLOCKCHAIN_ENVIRONMENTS
)

def deploy_fund_me():
    account = get_account()
    if network.show_active() not in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        price_feed_address = config["networks"][network.show_active()]["eth_usd_price_feed"]
    else:
        deploy_mocks()
        price_feed_address = MockV3Aggregator[-1].address

    fund_me = FundMe.deploy(
        price_feed_address,
        {'from': account}
    )

def deploy_cash():
    account = get_account()
    verifier = Verifier.deploy({"from": account})
    cash = Cash.deploy(verifier, {"from": account})

def main():
    deploy_cash()