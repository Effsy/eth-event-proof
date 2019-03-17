const DxiTriggerPostSellOrder = artifacts.require("DxiTriggerPostSellOrder");
const EventEmitterVerifier = artifacts.require("EventEmitterVerifier");
const EventEmitter = artifacts.require("EventEmitter");

module.exports = async (deployer) => {
  try {
      deployer.deploy(EventEmitter)
      .then(() => EventEmitter.deployed)
      .then(() => deployer.deploy(EventEmitterVerifier))
      .then(() => EventEmitterVerifier.deployed)
      .then(() => deployer.deploy(DxiTriggerPostSellOrder))
      .then(() => DxiTriggerPostSellOrder.deployed)

      console.log('Ion contracts deployed');
  } catch(err) {
    console.log('ERROR on deploy:',err);
  }

};