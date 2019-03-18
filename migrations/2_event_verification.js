const EventEmitter = artifacts.require("EventEmitter");
const EventEmitterVerifier = artifacts.require("EventEmitterVerifier"); 
const DxiTriggerPostSellOrder = artifacts.require("DxiTriggerPostSellOrder");
const Verifier = artifacts.require("Verifier");

module.exports = async (deployer) => {
  try {
      deployer.deploy(EventEmitter)
      .then(() => EventEmitter.deployed)
      .then(() => deployer.deploy(EventEmitterVerifier))
      .then(() => EventEmitterVerifier.deployed)
      .then(() => deployer.deploy(DxiTriggerPostSellOrder, EventEmitterVerifier.address))
      .then(() => DxiTriggerPostSellOrder.deployed)

      console.log('Ion contracts deployed');
  } catch(err) {
    console.log('ERROR on deploy:',err);
  }

};