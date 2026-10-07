const fs = require('fs');
const path = require('path');
const PopCore = require('../diagnose-core.js');

const fixturesPath = path.join(__dirname, 'differential_fixtures.json');
const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

const passCase = fixtures.cases.find(c => c.gw_stage === "Pass");
if (!passCase) {
    console.error("No passing case found in differential_fixtures.json");
    process.exit(1);
}

const inputs = passCase.inputs;
// Set evalTime to timestamp of the request
inputs.evalTime = parseInt(inputs.timestampStr, 10);

PopCore.diagnose(inputs).then(result => {
    if (result.firstFailedStage === null && !result.error) {
        console.log("SUCCESS: Golden Request Passed All Stages");
    } else {
        console.error("FAIL:", result);
        process.exit(1);
    }
});
