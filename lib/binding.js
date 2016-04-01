var binding = {};

try {
  binding = require('../build/' + process.platform + '/Release/sodium');
}
catch (e) {
  binding = require('/var/task/bin/sodium');
}

module.exports = binding;
