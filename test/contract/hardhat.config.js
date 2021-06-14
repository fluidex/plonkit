require("@nomiclabs/hardhat-waffle");
require("hardhat-gas-reporter");
module.exports = {
  solidity: {
    version: "0.6.7",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
  gasReporter: { enabled: true },
};
